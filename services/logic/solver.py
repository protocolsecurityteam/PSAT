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
from .terms import CALLER, Term, cheapest_first, fits, mk

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


def boolean(v: Any) -> Any:
    return v if z3.is_bool(v) else integer(v) != 0


def signed(v: Any, bits: int = 256) -> Any:
    low = integer(v) % 2**bits
    return z3.If(low >= 2 ** (bits - 1), low - 2**bits, low)


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
        if kind in ("len", "word", "elem"):
            if kind == "elem" and t[1][0] == "load":
                container = t[1]
                return go(mk("load", container[1], container[2], (*container[3], ("k", t[2]))))
            if kind == "len" and t[1][0] == "array":
                return go(t[1][1])
            value = go(t[1])
            if isinstance(value, (bytes, str, tuple, list)):
                if kind == "len":
                    return z3.IntVal(len(value))
                offset = number(go(t[2]))
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
        name = t[2]
        if isinstance(name, tuple) and name[:1] == ("slot",):
            root = number(go(name[1])) if isinstance(name[1], Term) else name[1]
            if root is None:
                return self.missing(t, "symbolic namespace")
            name = ("slot", root, name[2])
        path = tuple((k, go(v) if k == "k" and v[0] != "hash" else v) for k, v in t[3])
        concrete = all(k != "k" or number(v) is not None for k, v in path)
        try:
            if concrete:
                value = self.storage.read(address, name, tuple((k, number(v) if k == "k" else v) for k, v in path))
                return z3.BoolVal(value) if isinstance(value, bool) else z3.IntVal(value)
            self.storage.register_root(address, name)
            snap = self.storage.snapshot(address)
        except ValueError as exc:
            return self.missing(t, str(exc))
        if not snap.complete:
            self._dependencies[-1] = True
            self.issues.extend(snap.issues)
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
        av = z3.Int2BV(a, 256)
        bv = z3.Int2BV(b, 256) if b is not None else None
        if name in ("and", "or", "xor", "bnot", "shl", "shr", "sar"):
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
        kind, args = t[1:]
        types, values = [], []
        for arg in args:
            value = self.translate(arg)
            type_ = arg[2] if arg[0] in ("const", "arg") else arg[1] if arg[0] == "conv" else None
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


def project(formula: Term, translation: Translation, identity: Term = CALLER) -> SolutionSet:
    """Return an exact finite/cofinite set or the original symbolic predicate with qualifications."""
    if translation.limits.solver_ms <= 0:
        return SolutionSet(formula, identity, "symbolic", issues=(Issue("budget", "solver"),))
    selected = translation.translate(identity)
    goal = boolean(translation.translate(formula))
    issues = tuple(dict.fromkeys(translation.issues))
    assumptions = tuple(sorted(translation.assumptions))
    if issues:
        return SolutionSet(formula, identity, "symbolic", issues=issues, assumptions=assumptions)
    others = [v for t, v in translation.variables.items() if t != identity]
    # Bounds of existential variables belong inside the quantifier, not outside its negation.
    allowed = z3.And(*translation.bounds, goal)
    predicate = z3.Exists(others, allowed) if others else allowed
    domain = z3.And(selected >= 0, selected < ADDRESS)
    positive, negative = z3.Solver(), z3.Solver()
    for solver in (positive, negative):
        solver.set(timeout=translation.limits.solver_ms)
        solver.add(domain)
    positive.add(predicate)
    negative.add(z3.Not(predicate))
    members, excluded = [], []
    for _ in range(translation.limits.members + 1):
        for solver, found, representation in ((positive, members, "finite"), (negative, excluded, "cofinite")):
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
