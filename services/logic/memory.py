"""Bounded byte regions with absolute or symbolic addresses, never fabricated numbers."""

from .terms import _unmodelled, const, mk, mk_cmp, mk_ite, mk_op, mk_slice, packed_width

SPAN = 0x400
CALLDATA_COPY = mk("opaque", "calldatacopy", ())


def location(value):
    if value[0] == "const" and isinstance(value[1], int) and not isinstance(value[1], bool):
        return value[1] if 0 <= value[1] < SPAN else None
    if value[0] == "memory_address" and not _unmodelled(value):
        return value, 0
    if value[:2] in (("op", "add"), ("op", "sub")):
        a, b = value[2]
        if value[1] == "add" and a[0] == "const":
            a, b = b, a
        base = location(a)
        if base is not None and b[0] == "const" and isinstance(b[1], int):
            result = shift(base, b[1] if value[1] == "add" else -b[1])
            return result if 0 <= split(result)[1] < SPAN else None
    return None


def split(position):
    return (const(0), position) if isinstance(position, int) else position


def shift(position, amount):
    base, offset = split(position)
    offset += amount
    return offset if base == const(0) else (base, offset)


def difference(left, right):
    a, x = split(left)
    b, y = split(right)
    return x - y if a == b and not _unmodelled(a) else None


def _arena_floor(position):
    base, _ = split(position)
    if base[0] == "memory_address" and base[2][:1] == ("memory_arena",) and base[2][2] and len(base[2]) > 4:
        return base[2][4]
    return 0


def disjoint(a, length_a, b, length_b):
    if length_a == 0 or length_b == 0:
        return True
    if a is None or b is None:
        return False
    delta = difference(a, b)
    if delta is not None:
        return (length_a is not None and delta + length_a <= 0) or (length_b is not None and delta >= length_b)
    # A still well-formed compiler allocator starts beyond the scratch/header area.
    return (isinstance(a, int) and length_a is not None and a + length_a <= _arena_floor(b)) or (
        isinstance(b, int) and length_b is not None and b + length_b <= _arena_floor(a)
    )


def _length(word):
    if word[0] == "memory_fragment":
        return word[3]
    return None if word == CALLDATA_COPY or word[:2] == ("opaque", "returndatacopy") else 32


def clobbered(memory, start, length):
    return tuple((p, v) for p, v in memory if disjoint(p, _length(v), start, length))


def region_holds(memory, start, marker):
    for position, value in reversed(memory):
        if difference(position, start) == 0 and value == marker:
            return True
        if not disjoint(position, _length(value), start, None):
            return False
    return False


def copied_buffer(memory, start, data):
    """The copied input's extent with subsequent placed word/byte writes applied.

    This describes only the copied extent. It makes no claim about prior memory
    outside that extent, or about a write whose address/size is not placed.
    """
    patches = None
    for position, value in memory:
        delta = difference(position, start)
        if delta == 0 and value == CALLDATA_COPY:
            patches = []
            continue
        if patches is None:
            continue
        width = _length(value)
        if disjoint(position, width, start, None):
            continue
        if delta is None or width is None:
            return None
        skip = max(0, -delta)
        if value[0] == "memory_fragment":
            skip += value[2]
            word = value[1]
        else:
            word = value
        count = width + min(delta, 0)
        if count > 0:
            patches.append((max(delta, 0), word, skip, count))
    if patches is None:
        return None
    return mk("bytes_patch", data, tuple(patches)) if patches else data


def memory_bytes(memory, start, length, *, missing=None):
    if start is None or length is None or not 0 < length <= SPAN or split(start)[1] + length > SPAN:
        return None
    owner = [None] * length
    for i, (position, value) in enumerate(memory):
        delta = difference(position, start)
        if delta is None:
            if not disjoint(position, _length(value), start, length):
                owner[:] = [None] * length
            continue
        width = _length(value)
        for byte in range(max(delta, 0), min(delta + (32 if width is None else width), length)):
            owner[byte] = i
    if missing is None and any(i is None for i in owner):
        return None
    pieces = []
    b = 0
    while b < length:
        index = owner[b]
        end = b + 1
        while end < length and end - b < 32 and owner[end] == index:
            end += 1
        if index is None:
            assert missing is not None
            pieces.append(mk_slice(missing(b, end - b), 0, end - b))
            b = end
            continue
        position, word = memory[index]
        delta = difference(position, start)
        assert delta is not None
        offset = b - delta
        if word[0] == "memory_fragment":
            offset += word[2]
            word = word[1]
        pieces.append(mk_slice(word, offset, end - b))
        b = end
    return tuple(pieces)


def memory_uint(memory, position, length):
    pieces = memory_bytes(memory, position, length)
    if pieces is None:
        return None
    if len(pieces) == 1:
        return pieces[0][1] if length == 32 and pieces[0][0] == "slice" else pieces[0]
    result, left = const(0), length
    for piece in pieces:
        width = packed_width(piece)
        if width is None:
            return None
        left -= width
        result = mk_op("or", (result, mk_op("shl", (piece, const(8 * left)))))
    return result


def memory_word(memory, position):
    return memory_uint(memory, position, 32)


def buffer_memory(value, start: int | tuple = 0):
    from .abi_values import encoded_region

    layout = encoded_region(value, SPAN)
    if layout is None:
        return None
    size, chunks = layout
    return size, tuple((shift(start, off), mk("memory_fragment", word, 0, width)) for off, word, width in chunks)


def buffer_uint(value, offset, width, *, padded=False):
    if offset < 0 or not 0 < width <= 32:
        return None
    if value[0] == "bytes_prefix" and offset + width <= len(value[1]):
        return const(int.from_bytes(value[1][offset : offset + width], "big"))
    if value[0] == "bytes_patch" and offset + width <= buffer_min_length(value):
        base = buffer_uint(value[1], offset, width, padded=True)
        if base is not None:
            seed = (offset, mk("memory_fragment", mk_op("shl", (base, const(8 * (32 - width)))), 0, width))
            writes = tuple((at, mk("memory_fragment", word, skip, n)) for at, word, skip, n in value[2])
            projected = memory_uint((seed, *writes), offset, width)
            if projected is not None:
                return projected
    if padded and (
        value[0] in ("bytes_prefix", "bytes_slice", "bytes_patch")
        or (value[0] == "arg" and value[2] in ("bytes", "string"))
    ):
        word = mk("elem", value, const(offset))
        return word if width == 32 else mk_op("shr", (word, const(8 * (32 - width))))
    layout = buffer_memory(value)
    if layout is None:
        return None
    size, memory = layout
    count = max(0, min(width, size - offset))
    if count < width and not padded:
        return None
    word = memory_uint(memory, offset, count) if count else const(0)
    if count == width:
        return word
    return None if word is None else mk_op("shl", (word, const(8 * (width - count))))


def buffer_min_length(value):
    """A structural lower bound, never a sampled or guessed calldata length."""
    if value[0] == "bytes_prefix":
        return len(value[1])
    if value[0] == "bytes_patch":
        return buffer_min_length(value[1])
    if value[0] == "bytes_slice" and value[3][0] == "const" and type(value[3][1]) is int:
        return value[3][1] % 2**256
    layout = buffer_memory(value)
    return layout[0] if layout is not None else 0


def buffer_length(value):
    """The byte length without materializing a symbolic stream."""
    if value[0] == "bytes_slice":
        return mk("conv", "uint256", value[3])
    if value[0] == "bytes_patch":
        return buffer_length(value[1])
    if value[0] == "bytes_prefix":
        return mk("len", value)
    if value[0] == "arg" and value[2] in ("bytes", "string"):
        return mk("len", value)
    layout = buffer_memory(value)
    return const(layout[0]) if layout is not None else None


def prefix_word(value, offset):
    """One padded word of a fixed byte prefix followed by an arbitrary byte stream."""
    prefix, tail = value[1:]
    while tail[0] == "bytes_prefix":
        prefix += tail[1]
        tail = tail[2]
    at = mk("conv", "uint256", offset)
    n = const(len(prefix))
    # Before the join, the prefix word is already zero-padded; append the first
    # tail word at the join. EVM shifts of 256 bits or more produce zero.
    joined = mk_op(
        "or",
        (
            mk("elem", const(prefix, "bytes"), at),
            mk_op("shr", (mk("elem", tail, const(0)), mk_op("mul", (mk_op("sub", (n, at)), const(8))))),
        ),
    )
    return mk_ite(mk_cmp("lt", at, n), joined, mk("elem", tail, mk_op("sub", (at, n))))


def copied_byte(value, offset, previous):
    """A call copies at most the available return bytes; shorter replies preserve memory."""
    from .terms import mk_ite, unknown

    if value[0] == "ite":
        return mk_ite(value[1], copied_byte(value[2], offset, previous), copied_byte(value[3], offset, previous))
    layout = buffer_memory(value)
    if layout is None:
        return unknown("unsupported:return_copy")
    size, memory = layout
    return previous if offset >= size else memory_uint(memory, offset, 1)
