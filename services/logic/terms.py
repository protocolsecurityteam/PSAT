"""Terms: immutable tuples, so equal terms compare and hash equal and formulas share structure.

Values::

    ("caller",)  ("origin",)  ("this",)  ("sig",)  ("callvalue",)
    ("arg", name, type)                     an argument the caller chooses
    ("const", value, type)                  ints (addresses as ints), bools, strings
    ("time", kind)                          block.timestamp, block.number, ...
    ("load", contract, var, path)           storage; ``path`` is (("k", key) | ("f", field), ...)
    ("rawload", contract, slot)             an assembly ``sload``
    ("hash", kind, args)                    keccak256 / sha256 / ripemd160
    ("enc", kind, args)                     abi.encode* (only ever hashed or compared)
    ("signer", digest, v, r, s)             ecrecover: the identity that signed ``digest``
    ("call", target, signature, args, view) another contract's answer
    ("immutable", code, name)               an immutable of the code at ``code``
    ("item", value, index)                  one element of a tuple result
    ("ok", call, n)  ("caught", call, n)    whether that call returns, or reverts in the callee (a ``try``); ``n``
                                            return values expected, ``None`` if unknown
    ("len", value)  ("elem", value, index)  arrays
    ("slice", word, start, length)          bytes [start, start+length) of a word, big-endian (assembly memory)
    ("op", name, args)  ("conv", type, value)  ("ite", cond, then, else)
    ("unknown", reason)                     anything the lowering can't express

Conditions are values of bool type: ``("cmp", "eq" | "lt" | "le", a, b)``, ``("not", a)``, ``("and", frozenset)``,
``("or", frozenset)`` and bool constants. The constructors simplify as they build, which is what keeps the merge of
many branches small: ``(P and c) or (P and not c)`` is ``P``.
"""

from __future__ import annotations

import hashlib
from typing import Any


class Term(tuple):
    """A tuple interned through ``mk``: one object per distinct term, its hash computed once. Formulas share
    subterms heavily (every branch merge does), and an uncached tuple hash walks the whole expanded tree each time."""

    def __hash__(self) -> int:
        try:
            return self.__dict__["_hash"]
        except KeyError:
            h = self.__dict__["_hash"] = tuple.__hash__(self)
            return h

    def __eq__(self, other: object) -> bool:
        return self is other or tuple.__eq__(self, other)

    def __ne__(self, other: object) -> bool:
        equal = self.__eq__(other)
        return equal if equal is NotImplemented else not equal


_TABLE: dict[Term, Term] = {}


def mk(*parts: Any) -> Term:
    t = Term(parts)
    return _TABLE.setdefault(t, t)


_EPOCH = [0]


def reset_terms() -> None:
    """Drop the intern table between analyses; terms already built stay valid."""
    _TABLE.clear()
    _EPOCH[0] += 1
    for t in (TRUE, FALSE, CALLER, ORIGIN, THIS):
        _TABLE[t] = t


def term_epoch() -> int:
    """Which intern table terms built now belong to: bumped by every ``reset_terms``."""
    return _EPOCH[0]


def reintern(value: Any, memo: dict[int, Any] | None = None) -> Any:
    """``value`` (terms, and the tuples, lists, dicts and sets holding them) rebuilt in the current intern table, once
    per shared node. Terms kept from an earlier table are equal to today's but not identical, so comparing them walks
    both trees whole: exponential on a shared DAG."""
    memo = {} if memo is None else memo
    key = id(value)
    if key in memo:
        return memo[key]
    if isinstance(value, Term):
        out: Any = mk(*(reintern(x, memo) for x in value))
    elif isinstance(value, tuple):
        out = tuple(reintern(x, memo) for x in value)
    elif isinstance(value, list):
        out = [reintern(x, memo) for x in value]
    elif isinstance(value, dict):
        out = {reintern(k, memo): reintern(v, memo) for k, v in value.items()}
    elif isinstance(value, frozenset):
        out = frozenset(reintern(x, memo) for x in value)
    else:
        out = value
    memo[key] = out
    return out


TRUE: Term = mk("const", True, "bool")
FALSE: Term = mk("const", False, "bool")
CALLER: Term = mk("caller")
ORIGIN: Term = mk("origin")
THIS: Term = mk("this")
CALLDATA: Term = mk("arg", "msg.data", "bytes")  # the call's own data: its selector and arguments
WORD = 2**256

# Roots a value can depend on that differ between callers.
IDENTITY_KINDS = frozenset({"caller", "origin", "signer"})


def const(value: Any, type_: str = "uint256") -> Term:
    return mk("const", value, type_)


def mk_slice(word: Term, start: int, length: int) -> Term:
    """``length`` bytes of ``word``'s 32-byte big-endian form from ``start``: a value of exactly that width when it is
    the word's low end, so ``mstore(0x18, holder)`` hashed from 0x24 is ``holder``."""
    if is_const(word) and isinstance(word[1], int):
        whole = (int(word[1]) % WORD).to_bytes(32, "big")
        return const(int.from_bytes(whole[start : start + length], "big"), f"uint{8 * length}")
    if start + length == 32 and packed_width(word) == length:
        return word
    return mk("slice", word, start, length)


def unknown(reason: str) -> Term:
    return mk("unknown", reason)


def is_const(term: Term) -> bool:
    return term[0] == "const"


def mk_not(a: Term) -> Term:
    if a == TRUE:
        return FALSE
    if a == FALSE:
        return TRUE
    if a[0] == "not":
        return a[1]
    return mk("not", a)


def _parts(op: str, items: Any) -> list[Term]:
    out: list[Term] = []
    for item in items:
        if item[0] == op:
            out.extend(item[1])
        else:
            out.append(item)
    return out


def mk_and(items: Any) -> Term:
    parts = set(_parts("and", items))
    parts.discard(TRUE)
    if FALSE in parts or any(mk_not(p) in parts for p in parts):
        return FALSE
    if not parts:
        return TRUE
    if len(parts) == 1:
        return next(iter(parts))
    return mk("and", frozenset(parts))


def conjuncts(term: Term) -> frozenset:
    """The parts of a conjunction (the term itself when it is no ``and``)."""
    return term[1] if term[0] == "and" else frozenset({term})


_conjuncts = conjuncts


def mk_or(items: Any) -> Term:
    parts = set(_parts("or", items))
    parts.discard(FALSE)
    if TRUE in parts or any(mk_not(p) in parts for p in parts):
        return TRUE
    if not parts:
        return FALSE
    if len(parts) == 1:
        return next(iter(parts))
    # Factor shared conjuncts: (P and A) or (P and B) is P and (A or B); a residual that is empty means the branch
    # adds nothing over P, so the whole disjunction is P.
    conj = [_conjuncts(p) for p in parts]
    common = frozenset.intersection(*conj)
    if common:
        rest = mk_or([mk_and(c - common) for c in conj])
        return mk_and([*common, rest])
    # A or (not A and B) is A or B.
    for p in list(parts):
        stripped = {q: mk_and(_conjuncts(q) - {mk_not(p)}) for q in parts if q != p and mk_not(p) in _conjuncts(q)}
        if stripped:
            return mk_or([*(q for q in parts if q not in stripped), *stripped.values()])
    # Absorption: A or (A and B) is A.
    minimal = [c for c in conj if not any(other < c for other in conj)]
    if len(minimal) < len(conj):
        return mk_or([mk_and(c) for c in minimal])
    return mk("or", frozenset(parts))


def mk_ite(cond: Term, then: Term, other: Term) -> Term:
    if cond == TRUE or then == other:
        return then
    if cond == FALSE:
        return other
    if then == TRUE and other == FALSE:
        return cond
    if then == FALSE and other == TRUE:
        return mk_not(cond)
    return mk("ite", cond, then, other)


def mk_cmp(op: str, a: Term, b: Term) -> Term:
    """``op`` in eq, ne, lt, le, gt, ge; stored as eq, lt and le."""
    if op == "ne":
        return mk_not(mk_cmp("eq", a, b))
    if op == "gt":
        return mk_cmp("lt", b, a)
    if op == "ge":
        return mk_cmp("le", b, a)
    if is_const(a) and is_const(b) and _comparable(a[1], b[1]):
        x, y = _num(a[1]), _num(b[1])
        return TRUE if {"eq": x == y, "lt": x < y, "le": x <= y}[op] else FALSE
    if op == "eq" and is_const(a) and is_const(b) and isinstance(a[1], str) and isinstance(b[1], str) and a[2] == b[2]:
        return TRUE if a[1] == b[1] else FALSE  # two literals of one type: equal exactly when their text is
    if op in ("eq", "le") and a == b:
        return TRUE
    if op == "lt" and a == b:
        return FALSE
    if op == "eq":
        for x, y in ((a, b), (b, a)):
            if y == TRUE:
                return x
            if y == FALSE:
                return mk_not(x)
        return mk("cmp", "eq", *sorted((a, b), key=stable))
    return mk("cmp", op, a, b)


def _comparable(x: Any, y: Any) -> bool:
    return isinstance(x, (int, bool)) and isinstance(y, (int, bool))


def _num(x: Any) -> int:
    return int(x)


_FOLD = {
    "add": lambda x, y: (x + y) % WORD,
    "sub": lambda x, y: (x - y) % WORD,
    "mul": lambda x, y: (x * y) % WORD,
    "div": lambda x, y: x // y if y else 0,
    "mod": lambda x, y: x % y if y else 0,
    "and": lambda x, y: x & y,
    "or": lambda x, y: x | y,
    "xor": lambda x, y: x ^ y,
    "shl": lambda x, y: (x << y) % WORD if y < 256 else 0,
    "shr": lambda x, y: x >> y if y < 256 else 0,
    "pow": lambda x, y: pow(x, y, WORD),
}


def mk_op(name: str, args: tuple) -> Term:
    if all(is_const(a) and _comparable(a[1], 0) for a in args):
        values = [_num(a[1]) for a in args]
        if name in _FOLD and len(values) == 2:
            return const(_FOLD[name](*values))
        if name == "bnot" and len(values) == 1:
            return const(WORD - 1 - values[0])
    return mk("op", name, tuple(args))


def contains(term: tuple, kinds: frozenset) -> bool:
    """Whether ``term`` mentions any of ``kinds`` anywhere inside. Remembered on every interned term visited, per
    ``kinds``, so asking about each subterm of a formula in turn stays linear."""
    kinds = frozenset(kinds)

    def known(t: tuple) -> bool | None:
        return t.__dict__.get("_contains", {}).get(kinds) if isinstance(t, Term) else None

    def remember(t: tuple, value: bool) -> None:
        if isinstance(t, Term):
            t.__dict__.setdefault("_contains", {})[kinds] = value

    if not isinstance(term, tuple):
        return False
    stack: list[tuple[tuple, bool]] = [(term, False)]
    local: dict[int, bool] = {}
    while stack:
        t, expanded = stack.pop()
        if id(t) in local:
            continue
        cached = known(t)
        if cached is not None:
            local[id(t)] = cached
            continue
        if t and isinstance(t[0], str) and t[0] in kinds:
            local[id(t)] = True
            remember(t, True)
            continue
        children = [c for c in _children(t) if isinstance(c, tuple)]
        if expanded:
            value = any(local.get(id(c), False) for c in children)
            local[id(t)] = value
            remember(t, value)
            continue
        stack.append((t, True))
        stack.extend((c, False) for c in children if id(c) not in local)
    return local[id(term)]


def _children(t: tuple) -> list:
    """Nested tuples and frozensets of ``t``: a term's operands, or every element of a plain tuple of terms."""
    out: list = []
    for part in t[1:] if t and isinstance(t[0], str) else t:
        if isinstance(part, frozenset):
            out.extend(sorted(part, key=stable))
        elif isinstance(part, tuple):
            out.append(part)
    return out


_SIZE_CAP = 10**9


def stable(t: Any) -> bytes:
    """A digest of ``t``'s structure, the same in every process (``hash`` of a string isn't): the order the engine
    walks, evaluates and encodes terms in, so a verdict never depends on the interpreter's hash seed."""
    if isinstance(t, Term):
        cached = t.__dict__.get("_stable")
        if cached is not None:
            return cached
    if isinstance(t, frozenset):
        body = b"{" + b"".join(sorted(stable(x) for x in t))
    elif isinstance(t, tuple):
        body = b"(" + b"".join(stable(x) for x in t)
    else:
        body = repr(t).encode()
    digest = hashlib.blake2b(body, digest_size=12).digest()
    if isinstance(t, Term):
        t.__dict__["_stable"] = digest
    return digest


def size(t: Any) -> int:
    """How big ``t`` is written out (shared parts counted at each use, capped): the cost of evaluating it cold."""
    if isinstance(t, frozenset):
        return min(_SIZE_CAP, sum(size(x) for x in t))
    if not isinstance(t, tuple):
        return 0
    cache = t.__dict__ if isinstance(t, Term) else None
    if cache is not None and "_size" in cache:
        return cache["_size"]
    n = min(_SIZE_CAP, 1 + sum(size(x) for x in (t[1:] if t and isinstance(t[0], str) else t)))
    if cache is not None:
        cache["_size"] = n
    return n


def cheapest_first(t: Term) -> tuple:
    """The operands of an ``and``/``or``, smallest first: one false conjunct decides, and the cheap one may be it."""
    cache = t.__dict__
    if "_ordered" not in cache:
        cache["_ordered"] = tuple(sorted(t[1], key=lambda x: (size(x), stable(x))))
    return cache["_ordered"]


def subterms(term: tuple, kind: str) -> tuple[Term, ...]:
    """Every subterm of ``kind``, outermost first, without duplicates. Remembered on an interned term, which never
    changes: a decision asks the same formula for its arguments and constants many times."""
    cache = term.__dict__.setdefault("_subterms", {}) if isinstance(term, Term) else None
    if cache is not None and kind in cache:
        return cache[kind]
    out: list[Term] = []
    stack = [term]
    seen: set[int] = set()
    while stack:
        t = stack.pop()
        if not isinstance(t, tuple) or id(t) in seen:
            continue
        seen.add(id(t))
        if isinstance(t, Term) and t and t[0] == kind:
            out.append(t)
        stack.extend(_children(t))
    found = tuple(dict.fromkeys(out))
    if cache is not None:
        cache[kind] = found
    return found


def substitute(term: Term, kind: str, replace: Any) -> Term:
    """``term`` with every subterm of ``kind`` replaced by ``replace(subterm)``, rebuilt through the simplifying
    constructors so the result folds."""
    memo: dict[int, Any] = {}

    def go(t: Any) -> Any:
        if isinstance(t, frozenset):
            return frozenset(go(x) for x in t)
        if not isinstance(t, tuple):
            return t
        key = id(t)
        if key in memo:
            return memo[key]
        if t and t[0] == kind:
            out = replace(t)
        elif t and isinstance(t[0], str):
            parts = [go(p) for p in t[1:]]
            out = _rebuild(t[0], parts) if any(a is not b for a, b in zip(parts, t[1:])) else t
        else:
            parts = [go(p) for p in t]
            out = tuple(parts) if any(a is not b for a, b in zip(parts, t)) else t
        memo[key] = out
        return out

    return go(term)


def replace_terms(term: Term, mapping: dict[Term, Term], keep_subjects: bool = False) -> Term:
    """``term`` with each subterm in ``mapping`` replaced, rebuilt through the simplifying constructors.
    ``keep_subjects`` leaves the call an ``ok``/``caught`` asks about as it is: whether it returns is about the call
    itself, not about the value it returned."""
    memo: dict[int, Any] = {}

    def go(t: Any) -> Any:
        if isinstance(t, frozenset):
            return frozenset(go(x) for x in t)
        if not isinstance(t, tuple):
            return t
        key = id(t)
        if key in memo:
            return memo[key]
        if t in mapping:
            out = mapping[t]
        elif keep_subjects and t and t[0] in ("ok", "caught"):
            out = t
        elif t and isinstance(t[0], str):
            parts = [go(p) for p in t[1:]]
            out = _rebuild(t[0], parts) if any(a is not b for a, b in zip(parts, t[1:])) else t
        else:
            parts = [go(p) for p in t]
            out = tuple(parts) if any(a is not b for a, b in zip(parts, t)) else t
        memo[key] = out
        return out

    return go(term)


def assume_conjuncts(formula: Term, rounds: int = 3) -> Term:
    """``A and B`` is ``A and B[A := true]``: each top-level conjunct holds wherever the others mention it (a path
    condition merged into a value's ``ite``), so it is folded away there. Equivalent, and smaller."""
    for _ in range(rounds):
        if formula[0] != "and":
            return formula
        facts: dict[Term, Term] = {}
        for c in formula[1]:
            if c[0] == "not":
                facts[c[1]] = FALSE
            elif c[0] != "const":
                facts[c] = TRUE
        if not facts:
            return formula
        parts = []
        for c in formula[1]:
            own = c[1] if c[0] == "not" else c
            parts.append(replace_terms(c, {k: v for k, v in facts.items() if k is not own}, keep_subjects=True))
        rewritten = mk_and(parts)
        if rewritten is formula:
            return formula
        formula = rewritten
    return formula


def _rebuild(kind: str, parts: list) -> Any:
    if kind == "and":
        return mk_and(parts[0])
    if kind == "or":
        return mk_or(parts[0])
    if kind == "not":
        return mk_not(parts[0])
    if kind == "ite":
        return mk_ite(*parts)
    if kind == "cmp":
        return mk_cmp(*parts)
    if kind == "op":
        return mk_op(parts[0], tuple(parts[1]))
    return mk(kind, *parts)


def packed_width(term: Term) -> int | None:
    """Bytes ``term`` takes in a packed encoding, from its type."""
    kind = term[0]
    if kind == "ite":
        a, b = packed_width(term[2]), packed_width(term[3])
        return a if a == b else None
    if kind in ("callvalue", "calldatasize", "time", "balance", "codesize", "len", "hash"):
        return 32
    if kind == "slice":
        return term[3]
    type_ = (
        term[2]
        if kind in ("const", "arg")
        else term[1]
        if kind == "conv"
        else "address"
        if kind in ("caller", "origin", "this", "signer")
        else None
    )
    if not isinstance(type_, str) or "[" in type_ or "(" in type_:
        return None  # an array or tuple: as wide as what it holds
    if type_.startswith("address"):
        return 20
    if type_ == "bool":
        return 1
    for prefix in ("uint", "int"):
        if type_.startswith(prefix):
            return int(type_[len(prefix) :] or 256) // 8
    if type_.startswith("bytes") and type_ != "bytes":
        return int(type_[5:])
    return None
