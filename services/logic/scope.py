"""Whose positions a function's effects touch, read off its lowered writes (see ``SCOPE.md``): ``self`` when every
write on every way it returns stays inside entries the caller holds, ``none`` when it writes nothing at all, else
``shared``."""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from .terms import CALLER, FALSE, IDENTITY_KINDS, THIS, Term, _conjuncts, contains, subterms

# Inline assembly that acts outside the lowering's view: a call out, code created or destroyed, a delegatecall.
_ASSEMBLY_ACTS = re.compile(r"\b(call|callcode|delegatecall|create|create2|selfdestruct)\s*\(")


@dataclass(frozen=True)
class Scope:
    kind: str  # "self" | "shared" | "none"
    # (class, where) per write: own, authorized, credit, unchanged, shared.
    writes: tuple[tuple[str, str], ...] = ()


def _strip(t: Any) -> Any:
    while isinstance(t, tuple) and t and t[0] == "conv":
        t = t[2]
    return t


def _is_caller(t: Any) -> bool:
    return _strip(t) == CALLER


def _keys(load: Term) -> list[Term]:
    return [step for kind, step in load[3] if kind == "k"]


def _fields(path: tuple) -> tuple:
    return tuple(step for kind, step in path if kind == "f")


def _keyed_by_caller(key: Term) -> bool:
    """The caller itself, or a hash whose one identity input is the caller (``keccak256(abi.encode(caller, id))``)."""
    from .holders import _hash_parts

    if _is_caller(key):
        return True
    if isinstance(key, tuple) and key and key[0] == "hash":
        parts = _hash_parts(key)
        return sum(1 for p in parts if _is_caller(p)) == 1 and not any(
            contains(p, IDENTITY_KINDS) for p in parts if not _is_caller(p)
        )
    return False


def _held_entry(t: Any, key: Term) -> bool:
    """A stored value read at ``key`` (``_owners[tokenId]``): who holds that key, when compared with the caller."""
    t = _strip(t)
    return isinstance(t, tuple) and t[:1] == ("load",) and key in _keys(t) and not contains(t, IDENTITY_KINDS)


def _holder_is_caller(c: Term, key: Term) -> bool:
    return (
        c[0] == "cmp"
        and c[1] == "eq"
        and ((_is_caller(c[2]) and _held_entry(c[3], key)) or (_is_caller(c[3]) and _held_entry(c[2], key)))
    )


def _granted_by_holder(c: Term, key: Term) -> bool:
    """Reads an entry the holder of ``key`` keeps for the caller (``operatorApprovals[_owners[id]][caller]``)."""
    return any(
        len(ks) >= 2 and _held_entry(ks[0], key) and _is_caller(ks[-1])
        for load in subterms(c, "load")
        for ks in (_keys(load),)
    )


def _granted_by_argument(c: Term, key: Term) -> bool:
    """Reads what an address argument granted the caller (``allowance[from][caller]``)."""
    if not (key[0] == "arg" and str(key[2]).startswith("address")):
        return False
    return any(len(ks) >= 2 and ks[0] == key and _is_caller(ks[1]) for load in subterms(c, "load") for ks in (_keys(load),))


def _authorized(pc: Term, key: Term) -> bool:
    for c in _conjuncts(pc):
        if _holder_is_caller(c, key) or _granted_by_argument(c, key):
            return True
        if c[0] == "or" and any(_holder_is_caller(b, key) for b in c[1]):
            if all(_holder_is_caller(b, key) or _granted_by_holder(b, key) for b in c[1]):
                return True
    return False


def _debit(value: Term, old: Term) -> Term | None:
    """``d`` when ``value`` is ``old - d``."""
    if value[0] == "op" and value[1] == "sub" and len(value[2]) == 2 and value[2][0] == old:
        return value[2][1]
    return None


def _credit(value: Term, old: Term, written: set) -> Term | None:
    """``d`` when ``value`` is ``base + d``, ``base`` what the entry held before this call: ``old``, or ``old``
    unless it is an entry this call already wrote (``ite(caller == to, balances[caller] - d, balances[to])``)."""
    if value[0] != "op" or value[1] != "add" or len(value[2]) != 2:
        return None
    a, b = value[2]
    for base, d in ((a, b), (b, a)):
        if base == old or (base[0] == "ite" and base[3] == old and base[2] in written):
            return d
    return None


def _where(key: tuple) -> str:
    var = key[1]
    name = var if isinstance(var, str) else f"namespaced:{var[-1]}" if isinstance(var, tuple) and var else str(var)
    fields = ".".join(str(f) for f in _fields(key[2]))
    return f"{name}.{fields}" if fields else name


def _assembly_acts(function: Any) -> bool:
    try:
        nodes = function.all_nodes()
    except Exception as exc:
        if isinstance(exc, TimeoutError):
            raise
        return True
    return any(_ASSEMBLY_ACTS.search(str(getattr(n, "inline_asm", "") or "")) for n in nodes)


def classify(exits: list, lost: bool, function: Any, current: Callable[[Term], Any] | None = None) -> Scope:
    """``current(load)``: the location's value at the block (anything else when unread), for writes that put back
    what is there."""
    from .lower import _unwritten

    writes: list[tuple[str, str]] = []
    if lost:
        writes.append(("shared", "<writes not followed>"))
    if function is not None and _assembly_acts(function):
        writes.append(("shared", "<assembly call>"))
    for exit_ in exits:
        if exit_.pc == FALSE:
            continue
        if subterms(exit_.pc, "delegate") or any(subterms(v, "delegate") for v in exit_.store.values()):
            writes.append(("shared", "<delegatecall>"))
        debits: dict[tuple, set] = {}
        pending: list[tuple[tuple, Term, Term]] = []
        written = set(exit_.store.values())
        for key, value in exit_.store.items():
            if key[0] in ("emit", "transient"):
                continue
            if key[0] == "act":
                writes.append(("shared", f"<call out: {key[1][2] if key[1][0] == 'call' else key[1][1]}>"))
                continue
            if key[0] == "raw" or key[0] != THIS:
                writes.append(("shared", "<raw slot>" if key[0] == "raw" else "<another contract>"))
                continue
            old = _unwritten(key)
            if value == old:
                continue
            keys = [step for kind, step in key[2] if kind == "k"]
            if any(_keyed_by_caller(k) for k in keys):
                cls = "own"
            elif any(_authorized(exit_.pc, k) for k in keys if not contains(k, IDENTITY_KINDS)):
                cls = "authorized"
            else:
                pending.append((key, value, old))
                continue
            writes.append((cls, _where(key)))
            d = _debit(value, old)
            if d is not None:
                debits.setdefault((key[1], _fields(key[2])), set()).add(d)
        for key, value, old in pending:
            d = _credit(value, old, written)
            if d is not None and d in debits.get((key[1], _fields(key[2])), ()):
                writes.append(("credit", _where(key)))
            elif value[0] == "const" and current is not None and current(old) == value[1]:
                writes.append(("unchanged", _where(key)))
            else:
                writes.append(("shared", _where(key)))
    out = tuple(sorted(set(writes)))
    if any(cls == "shared" for cls, _ in out):
        return Scope("shared", out)
    return Scope("self" if any(cls != "unchanged" for cls, _ in out) else "none", out)


def render(t: Any, depth: int = 0) -> str:
    """A short reading of a term, for reporting a gate."""
    if not isinstance(t, tuple) or not t:
        return repr(t)
    if depth > 5:
        return "..."
    if not isinstance(t[0], str):
        return "(" + ", ".join(render(x, depth + 1) for x in t) + ")"
    kind = t[0]
    sub = lambda x: render(x, depth + 1)  # noqa: E731
    if kind == "const":
        v = t[1]
        return hex(v) if isinstance(v, int) and not isinstance(v, bool) and v > 2**64 else repr(v)
    if kind in ("and", "or"):
        return "(" + f" {kind} ".join(sorted(sub(x) for x in t[1])) + ")"
    if kind == "not":
        return "!" + sub(t[1])
    if kind == "cmp":
        return f"{sub(t[2])} {t[1]} {sub(t[3])}"
    if kind == "load":
        name = t[2] if isinstance(t[2], str) else f"namespaced:{t[2][-1]}"
        return name + "".join(f"[{sub(s)}]" if k == "k" else f".{s}" for k, s in t[3])
    if kind == "arg":
        return str(t[1])
    if kind in ("caller", "origin", "this"):
        return kind
    if kind == "call":
        return f"{sub(t[1])}.{t[2]}({', '.join(sub(a) for a in t[3])})"
    if kind in ("ok", "caught", "conv"):
        return sub(t[1] if kind != "conv" else t[2])
    if kind == "op":
        return f"{t[1]}({', '.join(sub(a) for a in t[2])})"
    if kind == "hash":
        return f"H({', '.join(sub(a) for a in t[2])})"
    return f"{kind}(" + ", ".join(sub(x) for x in t[1:]) + ")"
