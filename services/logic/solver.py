"""Queries over the complete predicate. No RPC executions, caller samples or relaxed gates."""

from __future__ import annotations

import hashlib
import re
from typing import Any, cast

import z3
from eth_abi.abi import encode
from eth_utils.crypto import keccak

from .model import BudgetExceeded, Issue, Limits, Reads, SolutionSet
from .storage import Storage
from .terms import (
    CALLER,
    TRUE,
    Term,
    cheapest_first,
    const,
    contains,
    fits,
    mk,
    mk_and,
    mk_cmp,
    mk_op,
    replace_terms,
    subterms,
)

WORD = 2**256
ADDRESS = 2**160


def number(value: Any) -> int | None:
    if isinstance(value, (int, bool)):
        return int(value)
    if isinstance(value, z3.ExprRef):
        v = z3.simplify(value)
        if z3.is_int_value(v):
            return cast(z3.IntNumRef, v).as_long()
        if z3.is_true(v) or z3.is_false(v):
            return int(z3.is_true(v))
    return None


def integer(v: Any) -> Any:
    return z3.If(v, 1, 0) if z3.is_bool(v) else z3.IntVal(v) if isinstance(v, int) else v


RESOURCE_OUTCOME = "unsupported:raw_call_resources"
RESOURCE_ASSUMPTION = "low-level calls receive enough gas to complete"


def _flag_test(t: Term) -> tuple[Term, int] | None:
    for flag, other in ((t[2], t[3]), (t[3], t[2])):
        if flag[:2] == ("unknown", RESOURCE_OUTCOME) and other[0] == "const" and other[1] in (0, 1):
            return flag, int(other[1])
    return None


def assume_resources(predicate: Term) -> tuple[Term, bool]:
    """Assume enough gas for each low-level call that the predicate only ever requires to succeed.

    Then raising the outcome to TRUE can only admit more, and with ample gas it is exact. An outcome
    that also appears negatively (a path that needs the call to fail, which a sender may force with
    little gas, subject to the 63/64 rule) or inside a non-Boolean term stays unknown.
    """
    negative: set[Term] = set()
    seen: set[tuple[Term, bool]] = set()
    stack = [(predicate, True)]
    while stack:
        t, positive = stack.pop()
        if (t, positive) in seen or not isinstance(t, tuple) or not t:
            continue
        seen.add((t, positive))
        if t[0] in ("and", "or"):
            stack.extend((c, positive) for c in t[1])
        elif t[0] == "not":
            stack.append((t[1], not positive))
        elif t[0] == "ite":
            stack.extend(((t[1], True), (t[1], False), (t[2], positive), (t[3], positive)))
        elif t[0] == "unknown" and t[1] == RESOURCE_OUTCOME:
            if not positive:
                negative.add(t)
        elif t[0] == "cmp" and t[1] == "eq" and (flag := _flag_test(t)) is not None:
            # Assembly reads the outcome as a 0/1 word: ``ok == 0`` is its negation, ``ok == 1`` itself.
            stack.append((flag[0], positive if flag[1] else not positive))
        else:
            negative.update(u for u in subterms(t, "unknown") if u[1] == RESOURCE_OUTCOME)
    assumed = {t: TRUE for t in subterms(predicate, "unknown") if t[1] == RESOURCE_OUTCOME and t not in negative}
    return (replace_terms(predicate, assumed), True) if assumed else (predicate, False)


def boolean(v: Any) -> Any:
    return v if z3.is_bool(v) else integer(v) != 0


def signed(v: Any, bits: int = 256) -> Any:
    low = integer(v) % 2**bits
    return z3.If(low >= 2 ** (bits - 1), low - 2**bits, low)


def word(value: z3.ArithRef) -> z3.BitVecRef:
    """Distribute word conversion over conditionals, preserving the expression DAG.

    Int2BV(If(c, a, b)) == If(c, Int2BV(a), Int2BV(b)). This lets Z3 fold
    concrete storage values before mixing integer and bitvector arithmetic.
    """
    converted: dict[int, z3.BitVecRef] = {}
    pending = [value]
    while pending:
        node = pending[-1]
        key = node.get_id()
        if key in converted:
            pending.pop()
            continue
        if z3.is_app_of(node, z3.Z3_OP_ITE):
            left, right = (cast(z3.ArithRef, node.arg(i)) for i in (1, 2))
            missing = [child for child in (left, right) if child.get_id() not in converted]
            if missing:
                pending.extend(missing)
                continue
            converted[key] = cast(z3.BitVecRef, z3.If(node.arg(0), converted[left.get_id()], converted[right.get_id()]))
        else:
            converted[key] = z3.Int2BV(node, 256)
        pending.pop()
    return converted[value.get_id()]


class Translation:
    def __init__(
        self,
        reads: Reads,
        contracts: Any,
        address: int,
        selector: int = 0,
        limits: Limits = Limits(),
        bindings: dict[Term, Any] | None = None,
    ):
        self.reads, self.contracts, self.address, self.selector = reads, contracts, address, selector
        self.limits, self.bindings = limits, bindings or {}
        self.memo: dict[Term, Any] = {}
        self.variables: dict[Term, Any] = {}
        self.bounds: list[Any] = []
        self.issues: list[Issue] = []
        self.assumptions: set[str] = set()
        self.storage: Storage | None = None
        self.uncertain: dict[Term, bool] = {}
        self._dependencies: list[bool] = []

    def missing(self, term: Term, detail: str | None = None, kind: str = "unsupported") -> Any:
        if self._dependencies:
            self._dependencies[-1] = True
        self.issues.append(Issue(kind, detail or str(term[1] if len(term) > 1 else term[0])))
        return self.variable(term)

    def variable(self, term: Term, type_: str = "uint256") -> Any:
        if term in self.variables:
            return self.variables[term]
        name = f"v{len(self.variables)}"
        if type_ == "bool":
            v = z3.Bool(name)
        else:
            v = z3.Int(name)
            width = 160 if type_ in ("address", "address payable") else 256
            match = re.fullmatch(r"(u?int|bytes)(\d+)", type_)
            if match:
                width = int(match[2]) * (8 if match[1] == "bytes" else 1)
            lo, hi = (-(2 ** (width - 1)), 2 ** (width - 1)) if type_.startswith("int") else (0, 2**width)
            self.bounds.append(z3.And(v >= lo, v < hi))
        self.variables[term] = v
        return v

    def byte_chunk(self, data: Term, index: Term):
        """Finite read-only array elimination: equal indices must have equal word values."""
        at = integer(self.translate(index))
        bound = self.bindings.get(data)
        if isinstance(bound, str):
            bound = bound.encode("utf-8")
        if isinstance(bound, bytes):
            fixed = number(at)
            if fixed is not None:
                start = 32 * fixed
                chunk = bound[start : start + 32] if fixed >= 0 else b""
                return z3.IntVal(int.from_bytes(chunk.ljust(32, b"\0"), "big"))
            stream = z3.K(z3.IntSort(), z3.IntVal(0))
            for i in range(0, len(bound), 32):
                stream = z3.Store(stream, i // 32, int.from_bytes(bound[i : i + 32].ljust(32, b"\0"), "big"))
            return cast(z3.ArithRef, z3.Select(stream, at))
        if data in self.bindings:
            return self.missing(mk("byte_chunk", data, index), "ABI bytes binding")
        fixed = number(at)
        if fixed is not None:
            index = const(fixed)
        term = mk("byte_chunk", data, index)
        if term in self.variables:
            return self.variables[term]
        previous = [(t, v) for t, v in self.variables.items() if t[0] == "byte_chunk" and t[1] == data]
        value = self.variable(term)
        for other, old in previous:
            self.bounds.append(z3.Implies(at == integer(self.translate(other[2])), value == old))
        return value

    def byte_window(self, data: Term, offset: Term):
        """One EVM byte window over a single caller-controlled stream, padded past its length."""
        bound = data[1] if data[0] == "const" else self.bindings.get(data)
        at = integer(self.translate(offset)) % WORD
        block, shift = at / 32, (at % 32) * 8
        aligned = number(shift) == 0
        if isinstance(bound, str):
            bound = bound.encode("utf-8")
        if isinstance(bound, bytes):
            position = number(at)
            if position is not None:
                return z3.IntVal(int.from_bytes(bound[position : position + 32].ljust(32, b"\0"), "big"))
            # Concrete streams need no quantified array: this is a fixed finite store.
            stream = z3.K(z3.BitVecSort(256), z3.BitVecVal(0, 256))
            for i in range(0, len(bound), 32):
                value = int.from_bytes(bound[i : i + 32].ljust(32, b"\0"), "big")
                stream = z3.Store(stream, z3.BitVecVal(i // 32, 256), z3.BitVecVal(value, 256))
            length = z3.IntVal(len(bound))
            left = z3.Select(stream, z3.Int2BV(block, 256))
            left_value = z3.BV2Int(left)
            right = z3.Select(stream, z3.Int2BV(block + 1, 256)) if not aligned else None
        else:
            if data in self.bindings:
                return self.missing(mk("elem", data, offset), "ABI bytes binding")
            index = mk_op("div", (mk("conv", "uint256", offset), const(32)))
            left_value = self.byte_chunk(data, index)
            left = word(left_value)
            right = word(self.byte_chunk(data, mk_op("add", (index, const(1))))) if not aligned else None
            length = integer(self.translate(mk("len", data)))
        available = cast(z3.ArithRef, z3.If(length <= at, 0, z3.If(length - at >= 32, 32, length - at)))
        mask = z3.BitVecVal(WORD - 1, 256) << z3.Int2BV((32 - available) * 8, 256)
        if aligned:
            return z3.If(length - at >= 32, left_value, z3.BV2Int(left & mask))
        assert right is not None
        combined = (left << z3.Int2BV(shift, 256)) | z3.LShR(right, z3.Int2BV(256 - shift, 256))
        return z3.BV2Int(combined & mask)

    def view_window(self, data: Term, offset: Term):
        """Read a byte view without inventing new independent input words."""
        at = integer(self.translate(offset)) % WORD
        length = integer(self.translate(mk("len", data)))
        if data[0] == "bytes_slice":
            origin = integer(self.translate(data[2])) % WORD
            source_at = mk_op("add", (data[2], offset))
            source = word(integer(self.translate(mk("elem", data[1], source_at))))
            available = cast(z3.ArithRef, z3.If(length <= at, 0, z3.If(length - at >= 32, 32, length - at)))
            mask = z3.BitVecVal(WORD - 1, 256) << z3.Int2BV((32 - available) * 8, 256)
            # Source offsets past the word domain pad with zero, never wrap to
            # the first byte of the source (even though EVM arithmetic wraps).
            return z3.If(origin + at >= WORD, 0, z3.BV2Int(source & mask))
        if data[0] == "bytes_patch":
            current = word(integer(self.translate(mk("elem", data[1], offset))))
            for position, value, skip, width in data[2]:
                if type(position) is not int or position < 0 or not 0 <= skip < skip + width <= 32:
                    return self.missing(mk("elem", data, offset), "unsupported:byte_patch")
                low = cast(z3.ArithRef, z3.If(at > position, at, position))
                high = cast(z3.ArithRef, z3.If(at + 32 < position + width, at + 32, position + width))
                high = cast(z3.ArithRef, z3.If(high < length, high, length))
                count, output_skip = high - low, low - at
                mask = z3.LShR(
                    z3.BitVecVal(WORD - 1, 256) << z3.Int2BV((32 - count) * 8, 256),
                    z3.Int2BV(output_skip * 8, 256),
                )
                source = word(integer(self.translate(value))) << z3.Int2BV((skip + low - position) * 8, 256)
                placed = z3.LShR(source, z3.Int2BV(output_skip * 8, 256))
                current = cast(z3.BitVecRef, z3.If(high > low, (current & ~mask) | (placed & mask), current))
            return z3.BV2Int(current)
        raise ValueError("not a byte view")

    def unbound(self):
        """An independent query with the same translation policy and pinned storage."""
        from copy import copy

        other = copy(self)
        Translation.__init__(other, self.reads, self.contracts, self.address, self.selector, self.limits)
        other.storage = self.storage
        return other

    def translate(self, term: Term) -> Any:
        if self.storage is None:
            self.storage = Storage(self.reads, self.contracts, self.limits, term)
        if term not in self.memo:
            self._dependencies.append(False)
            try:
                try:
                    value = self._translate(term)
                except BudgetExceeded as exc:
                    value = self.missing(term, str(exc), "budget")
            finally:
                self.uncertain[term] = self._dependencies.pop()
            self.memo[term] = z3.simplify(value) if isinstance(value, z3.ExprRef) else value
        if self._dependencies:
            self._dependencies[-1] |= self.uncertain[term]
        return self.memo[term]

    def _translate(self, t: Term) -> Any:
        if t in self.bindings:
            v = self.bindings[t]
            if isinstance(v, bytes) and t[0] == "arg" and t[2] != "bytes":
                v = int.from_bytes(v, "big")
            return z3.BoolVal(v) if isinstance(v, bool) else z3.IntVal(v) if isinstance(v, int) else v
        kind = t[0]
        go = self.translate
        if kind == "write_power":
            from .power import translate_power

            return translate_power(t, self)
        if kind == "storage_key_equal":
            self.assumptions.add("keccak256 storage-key collision resistance")
            return go(t[3])
        if kind == "memory_address":
            return self.missing(t, "unsupported:numeric_memory_address")
        if kind == "const":
            v = t[1]
            return z3.BoolVal(v) if isinstance(v, bool) else z3.IntVal(v) if isinstance(v, int) else v
        if kind in ("caller", "origin"):
            return self.variable(t, "address")
        if kind == "this":
            return z3.IntVal(self.address)
        if kind == "sig":
            return z3.IntVal(self.selector)
        if kind == "callvalue":
            return self.variable(t)
        if kind == "arg":
            if t[2] in ("bytes", "string") or "[" in t[2] or t[2].startswith("("):
                return self.missing(t, f"symbolic argument:{t[2]}")
            return self.variable(t, t[2])
        if kind == "byte_chunk":
            return self.byte_chunk(t[1], t[2])
        if kind == "bytes_prefix":
            tail = go(t[2])
            if isinstance(tail, str):
                tail = tail.encode("utf-8")
            return t[1] + tail if isinstance(tail, bytes) else self.missing(t, "symbolic byte sequence")
        if kind in ("bytes_slice", "bytes_patch"):
            data = go(t[1])
            if isinstance(data, str):
                data = data.encode("utf-8")
            if not isinstance(data, bytes):
                return self.missing(t, "symbolic byte sequence")
            if kind == "bytes_slice":
                start, count = number(go(t[2])), number(go(t[3]))
                if start is None or count is None:
                    return self.missing(t, "symbolic byte sequence")
                start, count = start % WORD, count % WORD
                if count > 2048:
                    return self.missing(t, "ABI bytes copy", "budget")
                return data[start : start + count].ljust(count, b"\0")
            output = bytearray(data)
            for offset, value, skip, width in t[2]:
                fixed = number(go(value))
                if fixed is None:
                    return self.missing(t, "symbolic byte sequence")
                count = max(0, min(width, len(output) - offset))
                raw = (fixed % WORD).to_bytes(32, "big")
                output[offset : offset + count] = raw[skip : skip + count]
            return bytes(output)
        if kind == "time":
            return z3.IntVal(self.reads.block_field(t[1]))
        if kind == "load":
            return self._load(t)
        if kind == "rawload":
            at, slot = number(go(t[1])), number(go(t[2]))
            if at is None or slot is None:
                return self.missing(t, "symbolic raw storage")
            return z3.IntVal(self.reads.storage(at, slot % WORD))
        if kind in ("unknown", "opaque", "assumed", "call", "delegate", "immutable", "constant"):
            if kind == "opaque" and str(t[1]).split("(")[0] in ("mulmod", "addmod") and len(t[2]) == 3:
                a, b, m = [integer(go(x)) for x in t[2]]
                return z3.If(m == 0, 0, (a * b if str(t[1]).startswith("mulmod") else a + b) % m)
            return self.missing(
                t,
                str(t[1]) if len(t) > 1 else kind,
                "not_verified"
                if kind == "unknown" and str(t[1]).startswith("unverified:")
                else "budget"
                if kind == "unknown" and "budget:" in str(t[1])
                else "unsupported",
            )
        if kind in ("and", "or"):
            values = []
            for x in cheapest_first(t):
                value = z3.simplify(boolean(go(x)))
                if not self.uncertain[x] and (
                    (kind == "and" and z3.is_false(value)) or (kind == "or" and z3.is_true(value))
                ):
                    self._dependencies[-1] = False
                    return value
                values.append(value)
            return z3.And(*values) if kind == "and" else z3.Or(*values)
        if kind == "not":
            return z3.Not(boolean(go(t[1])))
        if kind == "cmp":
            a, b = integer(go(t[2])), integer(go(t[3]))
            if not isinstance(a, z3.ExprRef) or not isinstance(b, z3.ExprRef):
                return z3.BoolVal(a == b) if t[1] == "eq" else self.missing(t, "comparison types")
            a, b = cast(z3.ArithRef, a), cast(z3.ArithRef, b)
            return a == b if t[1] == "eq" else a < b if t[1] == "lt" else a <= b
        if kind == "ite":
            condition = z3.simplify(boolean(go(t[1])))
            if z3.is_true(condition) or z3.is_false(condition):
                return go(t[2] if z3.is_true(condition) else t[3])
            a, b = go(t[2]), go(t[3])
            if not isinstance(a, z3.ExprRef) or not isinstance(b, z3.ExprRef):
                return self.missing(t, "conditional composite value")
            if z3.is_bool(a) != z3.is_bool(b):
                a, b = integer(a), integer(b)
            return z3.If(condition, a, b)
        if kind == "conv":
            value = integer(go(t[2]))
            if not isinstance(value, z3.ExprRef):
                return self.missing(t, "scalar conversion of composite value")
            type_ = t[1]
            if type_ == "bool":
                return boolean(value)
            match = re.fullmatch(r"(u?int|bytes)(\d+)", type_)
            bits = 160 if type_ in ("address", "address payable") else int(match[2]) if match else None
            if match and match[1] == "bytes":
                bits = int(match[2]) * 8
            if bits is None:
                return self.missing(t, f"conversion:{type_}")
            return signed(value, bits) if type_.startswith("int") else value % 2**bits
        if kind == "op":
            return self._operation(t)
        if kind == "enc":
            return self._encode(t)
        if kind == "hash":
            parts = [go(x) for x in t[2]]
            parts = [p.encode() if isinstance(p, str) else p for p in parts]
            if len(parts) == 1 and isinstance(parts[0], bytes):
                raw = parts[0]
            elif all(isinstance(x, bytes) for x in parts):
                raw = b"".join(parts)
            else:
                return self.missing(t, "symbolic hash preimage")
            fn = str(t[1]).split("(")[0]
            digest = (
                keccak(raw) if fn in ("keccak256", "sha3") else hashlib.sha256(raw).digest() if fn == "sha256" else None
            )
            return z3.IntVal(int.from_bytes(digest, "big")) if digest else self.missing(t, f"hash:{fn}")
        if kind == "signer":
            values = [number(go(x)) for x in t[1:]]
            if any(x is None for x in values):
                return self.missing(t, "signature relation requires signature inputs or a signing capability")
            from eth_keys.datatypes import Signature

            digest, v, r, s = cast(list[int], values)
            try:
                sig = Signature(vrs=(v - 27, r, s))
                result = sig.recover_public_key_from_msg_hash(digest.to_bytes(32, "big")).to_canonical_address()
                return z3.IntVal(int.from_bytes(result, "big"))
            except Exception as exc:
                from eth_keys.exceptions import BadSignature

                if isinstance(exc, (ValueError, BadSignature)):
                    return z3.IntVal(0)
                raise
        if kind == "abi_bytes_valid":
            value = t[1]
            if value[0] == "load":
                at = number(go(value[1]))
                path = tuple((k, number(go(v)) if k == "k" else v) for k, v in value[3])
                if at is None or any(k == "k" and v is None for k, v in path):
                    return self.missing(t, "symbolic ABI bytes layout")
                try:
                    assert self.storage is not None
                    code = number(go(value[4][1])) if len(value) > 4 else None
                    word = self.storage.bytes_header(at, value[2], path, code)
                except ValueError:
                    return self.missing(t, "ABI bytes layout")
                short = word % 2 == 0
                length = (word % 256) // 2 if short else word // 2
                if (short and length > 31) or (not short and length < 32):
                    return z3.BoolVal(False)
                if length > 2048:
                    return self.missing(t, "ABI bytes copy", "budget")
                return z3.BoolVal(True)
            if value[0] == "const" and isinstance(value[1], (str, bytes)):
                data = value[1].encode("utf-8") if isinstance(value[1], str) else value[1]
                return z3.BoolVal(True) if len(data) <= 2048 else self.missing(t, "ABI bytes copy", "budget")
            if value[0] in ("arg", "enc", "calldata", "array", "bytes_prefix", "bytes_slice", "bytes_patch"):
                return z3.BoolVal(True)
            return self.missing(t, "ABI bytes value")
        if kind == "len" and t[1][0] == "bytes_prefix":
            length = integer(go(mk("len", t[1][2]))) + len(t[1][1])
            self.bounds.append(length < WORD)
            return length
        if kind == "len" and t[1][0] == "bytes_slice":
            return integer(go(t[1][3])) % WORD
        if kind == "len" and t[1][0] == "bytes_patch":
            return go(mk("len", t[1][1]))
        if kind in ("len", "abi_word", "elem") and t[1][0] == "enc":
            from .abi_values import encoded_region

            layout = encoded_region(t[1])
            if layout is not None:
                size, chunks = layout
                if kind == "len":
                    return z3.IntVal(size)
                data = mk("bytes_patch", const(bytes(size), "bytes"), tuple((at, v, 0, n) for at, v, n in chunks))
                return go(mk("elem", data, const(32 * t[2]) if kind == "abi_word" else t[2]))
        if kind in ("abi_word", "elem") and t[1][0] in ("bytes_slice", "bytes_patch"):
            return self.view_window(t[1], const(32 * t[2]) if kind == "abi_word" else t[2])
        if kind in ("abi_word", "elem") and t[1][0] == "bytes_prefix":
            from .memory import prefix_word

            go(mk("len", t[1]))  # A concatenated stream must still fit the EVM size domain.
            return go(prefix_word(t[1], const(32 * t[2]) if kind == "abi_word" else t[2]))
        if kind in ("abi_word", "elem") and (
            (t[1][0] == "arg" and t[1][2] in ("bytes", "string"))
            or (t[1][0] == "const" and isinstance(t[1][1], (bytes, str)))
        ):
            if kind == "abi_word" and (type(t[2]) is not int or t[2] < 0):
                return self.missing(t, "ABI word index")
            return self.byte_window(t[1], const(32 * t[2]) if kind == "abi_word" else t[2])
        if kind == "abi_word" or (kind == "len" and t[1][0] == "arg" and t[1][2] in ("bytes", "string")):
            data = self.bindings.get(t[1])
            if isinstance(data, str):
                data = data.encode("utf-8")
            if kind == "abi_word" and t[1][0] != "arg":
                data = go(t[1])
                if isinstance(data, str):
                    data = data.encode("utf-8")
                if not isinstance(data, bytes):
                    return self.missing(t, "ABI word requires decoded bytes")
            if isinstance(data, bytes):
                if kind == "len":
                    return z3.IntVal(len(data))
                offset = 32 * t[2]
                return z3.IntVal(int.from_bytes(data[offset : offset + 32].ljust(32, b"\0"), "big"))
            if t[1] in self.bindings:
                return self.missing(t, "ABI bytes binding")
            # Scalar decoding reads disjoint 32-byte words of this same byte sequence.
            # Its minimum length and per-type validation are explicit path conditions.
            return self.variable(t)
        if kind in ("len", "word", "elem"):
            if kind == "elem" and t[1][0] == "load":
                from .cells import child_load

                container = t[1]
                return go(child_load(container, (("k", t[2]),)))
            if kind == "len" and t[1][0] == "array":
                return go(t[1][1])
            value = go(t[1])
            if isinstance(value, str):
                value = value.encode("utf-8")
            if isinstance(value, (bytes, tuple, list)):
                if kind == "len":
                    return z3.IntVal(len(value))
                offset = number(go(t[2]))
                if kind == "elem" and isinstance(value, bytes) and offset is not None and offset >= 0:
                    # Byte containers expose a word from this byte offset: byte_at()
                    # extracts its high byte, and calldataload reads the whole word.
                    return z3.IntVal(int.from_bytes(value[offset : offset + 32].ljust(32, b"\0"), "big"))
                if offset is not None and 0 <= offset < len(value):
                    if kind == "word":
                        if not isinstance(value, bytes) or offset + 32 > len(value):
                            return self.missing(t, "memory beyond bytes argument")
                        return z3.IntVal(int.from_bytes(value[offset : offset + 32], "big"))
                    return z3.IntVal(value[offset])
            return self.missing(t, f"dynamic {kind}")
        if kind == "slice":
            value = number(go(t[1]))
            if value is not None:
                return z3.IntVal(int.from_bytes((value % WORD).to_bytes(32, "big")[t[2] : t[2] + t[3]], "big"))
            return (integer(go(t[1])) / 2 ** (8 * (32 - t[2] - t[3]))) % 2 ** (8 * t[3])
        if kind in ("balance", "codesize", "code"):
            at = number(go(t[1]))
            if at is not None:
                if kind == "balance":
                    value = integer(go(mk("callvalue")))
                    credit = value if at == self.address else z3.IntVal(0)
                    debit = z3.If(integer(go(CALLER)) == at, value, 0)
                    return self.reads.balance(at) + credit - debit
                return z3.IntVal(len(self.reads.code(at)))
        return self.missing(t, f"term:{kind}")

    def _load(self, t: Term) -> Any:
        assert self.storage is not None
        go = self.translate
        address = number(go(t[1]))
        if address is None:
            return self.missing(t, "symbolic storage address")
        code = number(go(t[4][1])) if len(t) > 4 else None
        if len(t) > 4 and code is None:
            return self.missing(t, "symbolic storage code context")
        if len(t) > 4 and (t[4][2] is None or t[4][3] is None):
            if code not in getattr(self.contracts, "own_sources", {}):
                return self.missing(t, "unplaced storage code context")
        name = t[2]
        if isinstance(name, tuple) and name[:1] == ("slot",):
            root = number(go(name[1])) if isinstance(name[1], Term) else name[1]
            if root is None:
                return self.missing(t, "symbolic namespace")
            name = ("slot", root, name[2])
        path = tuple((k, go(v) if k == "k" and v[0] != "hash" else v) for k, v in t[3])
        concrete = all(k != "k" or number(v) is not None or isinstance(v, (str, bytes)) for k, v in path)
        try:
            if concrete:
                from .abi_values import from_name, static_words

                meta = t[4] if len(t) > 4 else None
                if meta and meta[2] is not None and meta[3] is not None and static_words(from_name(meta[5])) == 1:
                    slot, offset = number(go(meta[2])), number(go(meta[3]))
                    if slot is None or offset is None:
                        return self.missing(t, "symbolic physical storage")
                    value = self.storage.read_cell(address, slot, offset, meta[4], meta[5])
                else:
                    value = self.storage.read(
                        address,
                        name,
                        tuple((k, number(v) if k == "k" and number(v) is not None else v) for k, v in path),
                        code,
                    )
                return z3.BoolVal(value) if isinstance(value, bool) else z3.IntVal(value)
            deferred = self._defer_load(address, name, path, code)
            if deferred is not None:
                return deferred
            if len(t) > 4 and t[4][2] is not None:
                from .cells import annotate

                source = self.storage.contract(address, code)
                actual = annotate(source, t[4][1], (t[1], t[2], t[3]))[3] if source is not None else None
                if actual is None or actual[2:] != t[4][2:]:
                    return self.missing(t, "storage code layout does not match physical cell")
            self.storage.register_root(address, name, code)
            snap = self.storage.snapshot(address, code)
        except ValueError as exc:
            return self.missing(t, str(exc))
        if not snap.complete:
            self._dependencies[-1] = True
            self.issues.extend(snap.issues)
            if snap.slot_count is not None:
                self.issues.append(Issue("enumeration", f"{address:#x}: {len(snap.unexplained)} unattributed slots"))
            default = self.variable(t)
        else:
            default = z3.IntVal(0)
            self.assumptions.add("keccak256 storage-key collision resistance")
        result = default
        for stored_path, value in snap.entries.get(name, ()):
            if len(stored_path) != len(path):
                continue
            conditions = []
            for (kind, key), (stored_kind, stored_key) in zip(path, stored_path):
                if kind != stored_kind or (kind == "f" and key != stored_key):
                    break
                if kind == "k":
                    conditions.append(
                        self._key_equals(key, stored_key, snap.preimages)
                        if isinstance(key, Term)
                        else integer(key) == stored_key
                    )
            else:
                result = z3.If(z3.And(*conditions), int(value), integer(result))
        return result

    def _defer_load(self, address: int, name: Any, path: tuple, code: int | None = None) -> Any:
        return None

    def _key_equals(self, term: Term, key: int, preimages: dict[int, bytes]) -> Any:
        """Invert a known hash equality through its verified encoding, never guess a preimage."""
        from eth_abi.abi import decode

        from .terms import packed_width

        if term[0] != "hash" or str(term[1]).split("(")[0] not in ("keccak256", "sha3"):
            return integer(self.translate(term)) == key
        preimage = preimages.get(key)
        parts = term[2]
        if preimage is None or len(parts) != 1 or parts[0][0] != "enc":
            return self.missing(mk("unknown", f"hash_key:{key}", term), "hash-key preimage") != 0
        encoding = parts[0]
        args = encoding[2]
        types = [
            a[2]
            if a[0] in ("const", "arg")
            else a[1]
            if a[0] == "conv"
            else "address"
            if a[0] in ("caller", "origin", "this")
            else None
            for a in args
        ]
        try:
            if any(t is None for t in types):
                raise ValueError("untyped encoding")
            types = cast(list[str], types)
            if encoding[1] == "abi.encode":
                values = decode(types, preimage)
                if encode(types, values) != preimage:
                    raise ValueError("noncanonical preimage")
            elif encoding[1] == "abi.encodePacked":
                widths = [packed_width(a) for a in args]
                if any(w is None for w in widths):
                    raise ValueError("variable-length packed encoding")
                widths = cast(list[int], widths)
                if sum(widths) != len(preimage):
                    raise ValueError("variable-length packed encoding")
                values, offset = [], 0
                for type_, width in zip(types, widths):
                    raw = preimage[offset : offset + width]
                    offset += width
                    value = int.from_bytes(raw, "big", signed=type_.startswith("int"))
                    values.append(value)
            else:
                raise ValueError("encoding")
            conditions = []
            for arg, value in zip(args, values):
                if isinstance(value, bytes):
                    value = int.from_bytes(value, "big")
                elif isinstance(value, str) and value.startswith("0x"):
                    value = int(value, 16)
                if not isinstance(value, (int, bool)):
                    raise ValueError("dynamic preimage")
                conditions.append(integer(self.translate(arg)) == int(value))
            self.assumptions.add("keccak256 preimage and collision resistance")
            return z3.And(*conditions)
        except (ValueError, TypeError):
            return self.missing(mk("unknown", f"hash_key:{key}", term), "hash-key encoding") != 0

    def _operation(self, t: Term) -> Any:
        name, terms = t[1:]
        if name == "fits":
            op, a, b, bits, sign = terms
            x, y = integer(self.translate(a)), integer(self.translate(b))
            fixed = number(x), number(y)
            if None not in fixed:
                return z3.BoolVal(fits(op[1], cast(int, fixed[0]), cast(int, fixed[1]), bits[1], sign[1]))
            raw = x + y if op[1] == "add" else x - y if op[1] == "sub" else x * y if op[1] == "mul" else None
            if raw is None:
                return self.missing(t, f"checked {op[1]}")
            lo, hi = (-(2 ** (bits[1] - 1)), 2 ** (bits[1] - 1)) if sign[1] else (0, 2 ** bits[1])
            return z3.And(raw >= lo, raw < hi)
        vals = [integer(self.translate(x)) for x in terms]
        if not all(isinstance(v, z3.ExprRef) for v in vals):
            return self.missing(t, f"arithmetic:{name}")
        a = vals[0]
        b = vals[1] if len(vals) > 1 else None
        if name in ("add", "sub", "mul"):
            return (a + b if name == "add" else a - b if name == "sub" else a * b) % WORD
        if name in ("div", "mod"):
            return z3.If(b == 0, 0, a / b if name == "div" else a % b)
        if name in ("sdiv", "smod"):
            x, y = signed(a), signed(b)

            def absolute(v: Any) -> Any:
                return z3.If(v < 0, -v, v)

            q = absolute(x) / absolute(y) if name == "sdiv" else absolute(x) % absolute(y)
            negative = z3.Xor(x < 0, y < 0) if name == "sdiv" else x < 0
            return cast(z3.ArithRef, z3.If(y == 0, 0, z3.If(negative, -q, q))) % WORD
        if name in ("and", "or", "xor", "bnot", "shl", "shr", "sar"):
            av = word(a)
            bv = word(b) if b is not None else None
            v = (
                (av & bv)
                if name == "and"
                else (av | bv)
                if name == "or"
                else (av ^ bv)
                if name == "xor"
                else ~av
                if name == "bnot"
                else (av << bv)
                if name == "shl"
                else z3.LShR(av, bv)
                if name == "shr"
                else av >> bv
            )
            return z3.BV2Int(v)
        if name == "pow":
            x, y = number(a), number(b)
            if x is not None and y is not None:
                return z3.IntVal(pow(x, y, WORD))
        if name in ("byte", "signextend", "clz"):
            from .terms import _EXACT

            nums = [number(v) for v in vals]
            if all(v is not None for v in nums):
                nums = cast(list[int], nums)
                return z3.IntVal(256 - (nums[0] % WORD).bit_length() if name == "clz" else _EXACT[name](*nums))
        return self.missing(t, f"symbolic operation:{name}")

    def _encode(self, t: Term) -> Any:
        from .abi_values import encoded_region

        layout = encoded_region(t)
        if layout is not None:
            data = bytearray(layout[0])
            for offset, word, width in layout[1]:
                value = number(self.translate(word))
                if value is None:
                    return self.missing(t, "symbolic ABI encoding")
                data[offset : offset + width] = (value % WORD).to_bytes(32, "big")[:width]
            return bytes(data)
        kind, args = t[1:3]
        types, values = [], []
        for arg in args:
            value = self.translate(arg)
            type_ = arg[2] if arg[0] in ("const", "arg") else arg[1] if arg[0] == "conv" else None
            if kind == "abi.encodePacked" and arg[0] == "slice" and 1 <= arg[3] <= 32:
                # A memory slice has this exact byte length, independent of its source type.
                type_ = f"uint{8 * arg[3]}"
            n = number(value)
            if n is not None and type_ is not None:
                value = n
                if type_ == "bool":
                    value = bool(n)
                elif type_ == "address":
                    value = f"0x{n:040x}"
                elif type_.startswith("bytes") and type_[5:].isdigit():
                    value = n.to_bytes(int(type_[5:]), "big")
            elif isinstance(value, (bytes, str)):
                type_ = type_ or "bytes"
            else:
                return self.missing(t, "symbolic ABI encoding")
            types.append(type_)
            values.append(value)
        try:
            if kind == "abi.encodePacked":
                from eth_abi.packed import encode_packed

                return encode_packed(types, values)
            if kind == "abi.encodeWithSelector":
                return values[0] + encode(types[1:], values[1:])
            if kind == "abi.encodeWithSignature":
                return keccak(text=values[0])[:4] + encode(types[1:], values[1:])
            return encode(types, values)
        except (ValueError, TypeError):
            return self.missing(t, "ABI encoding")

    def truth(self, formula: Term) -> bool | None:
        expression = z3.simplify(boolean(self.translate(formula)))
        if self.uncertain[formula]:
            return None
        if z3.is_true(expression) or z3.is_false(expression):
            return z3.is_true(expression)
        return None


class _DeferredStorage(Translation):
    """Unknown keyed storage is fixed state, represented by consistent functions of its keys.

    Function interpretations never enter the existential call-argument variables. The
    projection must be proved independent of every interpretation before using it.
    """

    def __init__(self, original: Translation):
        super().__init__(
            original.reads, original.contracts, original.address, original.selector, original.limits, original.bindings
        )
        self.state_functions: dict[tuple, Any] = {}

    def _defer_load(self, address: int, name: Any, path: tuple, code: int | None = None) -> Any:
        from .layout import _size, locate

        contract = self.storage.contract(address, code) if self.storage is not None else self.contracts.get(address)
        dummy = tuple((kind, 0 if kind == "k" else key) for kind, key in path)
        where = locate(contract, name, dummy) if contract is not None else None
        if where is None or _size(where[2]) is None:
            return self.missing(mk("unknown", "unsupported:deferred_storage_layout"))
        keys = [integer(key) for kind, key in path if kind == "k"]
        if not all(isinstance(key, z3.ArithRef) for key in keys):
            return self.missing(mk("unknown", "unsupported:deferred_storage_layout"))
        root = address, code, name, tuple((kind, None if kind == "k" else key) for kind, key in path)
        if root not in self.state_functions:
            self.state_functions[root] = z3.Function(
                f"storage{len(self.state_functions)}", *([z3.IntSort()] * len(keys)), z3.IntSort()
            )
        return self.state_functions[root](*keys)


def _projected_goal(formula: Term, translation: Translation, identity: Term):
    if translation.storage is None:
        translation.storage = Storage(translation.reads, translation.contracts, translation.limits, formula)
    else:
        translation.storage.constants.update(
            int(t[1]) for t in subterms(formula, "const") if isinstance(t[1], (int, bool))
        )
    selected = translation.translate(identity)
    goal = boolean(translation.translate(formula))
    others = [v for t, v in translation.variables.items() if t != identity]
    return selected, others, z3.And(*translation.bounds, goal)


def _exists(others, body):
    return z3.Exists(others, body) if others else body


def _state_independent(formula: Term, original: Translation, identity: Term):
    """Return a projection only after proving it is identical for all deferred storage.

    Zero-valued storage supplies a candidate expression, never evidence about chain state.
    UNSAT of a difference query certifies that every possible fixed storage interpretation
    has exactly the same caller set, with the call arguments quantified inside each set.
    """
    if type(original) is not Translation or not any(
        contains(load, frozenset({"caller", "origin", "signer", "arg"})) for load in subterms(formula, "load")
    ):
        return None
    translated = _DeferredStorage(original)
    selected, others, body = _projected_goal(formula, translated, identity)
    if translated.issues or not translated.state_functions:
        return None
    candidate = z3.substitute_funs(body, *((f, z3.IntVal(0)) for f in translated.state_functions.values()))
    verifier = z3.Solver()
    verifier.set(timeout=original.limits.solver_ms)
    verifier.add(selected >= 0, selected < ADDRESS, _exists(others, body) != _exists(others, candidate))
    if verifier.check() != z3.unsat:
        return None
    return translated, selected, others, candidate


def project(formula: Term, translation: Translation, identity: Term = CALLER) -> SolutionSet:
    """Project callers over nonzero addresses; other address-valued identities retain zero."""
    formula, assumed = assume_resources(formula)
    if identity == CALLER:
        formula = mk_and([formula, mk_cmp("lt", const(0), CALLER)])
    if translation.limits.solver_ms <= 0:
        return SolutionSet(formula, identity, "symbolic", issues=(Issue("budget", "solver"),))
    independent = _state_independent(formula, translation, identity)
    if independent is not None:
        translation, selected, others, body = independent
    else:
        selected, others, body = _projected_goal(formula, translation, identity)
    issues = tuple(dict.fromkeys(translation.issues)) if translation.uncertain.get(formula, True) else ()
    assumptions = tuple(sorted(translation.assumptions | ({RESOURCE_ASSUMPTION} if assumed else set())))
    if issues:
        return SolutionSet(formula, identity, "symbolic", issues=issues, assumptions=assumptions)
    domain = z3.And(selected >= 0, selected < ADDRESS)
    positive, negative = z3.Solver(), z3.Solver()
    for solver in (positive, negative):
        solver.set(timeout=translation.limits.solver_ms)
        solver.add(domain)
    # Existence over the other inputs is satisfiability with them free; only the complement needs the quantifier.
    positive.add(body)
    negative.add(z3.Not(_exists(others, body)))
    members, excluded = [], []
    # A side whose solver ran out of time once: asking again spends the same budget for the same answer.
    spent: set[str] = set()
    for _ in range(translation.limits.members + 1):
        if len(spent) == 2:
            break
        for solver, found, representation in ((positive, members, "finite"), (negative, excluded, "cofinite")):
            if representation in spent:
                continue
            result = solver.check()
            if result == z3.unsat:
                return SolutionSet(
                    formula,
                    identity,
                    representation,
                    tuple(sorted(members)) if representation == "finite" else (),
                    tuple(sorted(excluded)) if representation == "cofinite" else (),
                    assumptions=assumptions,
                )
            if result == z3.unknown:
                issues = (*issues, Issue("solver", solver.reason_unknown()))
                spent.add(representation)
                continue
            if len(found) >= translation.limits.members:
                continue
            value = cast(z3.IntNumRef, solver.model().eval(selected, model_completion=True)).as_long()
            found.append(value)
            solver.add(selected != value)
    return SolutionSet(
        formula,
        identity,
        "symbolic",
        tuple(sorted(members)),
        issues=tuple(dict.fromkeys((*issues, Issue("budget", "materialisation")))),
        assumptions=assumptions,
    )
