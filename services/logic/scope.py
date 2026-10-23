"""Whose positions a function's effects touch, read off its lowered writes (see ``SCOPE.md``): ``self`` when every
write on every way it returns stays inside entries the caller holds, ``none`` when it writes nothing at all, else
``shared``."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from .terms import CALLER, FALSE, IDENTITY_KINDS, THIS, Term, conjuncts, contains, stable, subterms

# Inline assembly that acts outside the lowering's view: a call out, code created or destroyed, a delegatecall.
_ASSEMBLY_ACTS = re.compile(r"\b(call|callcode|delegatecall|create|create2|selfdestruct)\s*\(")


@dataclass(frozen=True)
class Scope:
    kind: str  # "self" | "shared" | "none"
    # (class, where) per write: own, authorized, credit, unchanged, or shared.
    writes: tuple[tuple[str, str], ...] = ()


def _strip(t: Any) -> Any:
    while isinstance(t, tuple) and t and t[0] == "conv":
        t = t[2]
    return t


def _is_caller(t: Any) -> bool:
    return _strip(t) == CALLER


def _keys(path: tuple) -> list[Term]:
    return [step for kind, step in path if kind == "k"]


def _fields(path: tuple) -> tuple:
    return tuple(step for kind, step in path if kind == "f")


def _hash_inputs(key: Term) -> list:
    """A hashed key's inputs, an encoding's items in its place (``keccak256(abi.encode(who, id))``)."""
    out = []
    for item in key[2]:
        items = item[2] if isinstance(item, tuple) and item and item[0] == "enc" else (item,)
        out.extend(_strip(x) for x in items)
    return out


def _owned_key(key: Term) -> bool:
    """A key that is the caller's own position: the caller, or a hash whose first input is the caller and whose
    other inputs name nobody (``keccak256(abi.encode(caller, id))``, not ``keccak256(abi.encode(victim, caller))``)."""
    if _is_caller(key):
        return True
    if isinstance(key, tuple) and key and key[0] == "hash":
        parts = _hash_inputs(key)
        return bool(parts) and _is_caller(parts[0]) and not any(contains(p, IDENTITY_KINDS) for p in parts[1:])
    return False


def _load_key(t: Any) -> Any:
    t = _strip(t)
    return t if isinstance(t, tuple) and t[:1] == ("load",) else None


def _requires_truthy(c: Term, wanted: Any) -> bool:
    """Whether condition ``c`` holds only where an entry ``wanted(load)`` picks out is nonzero: the entry itself (a
    flag), ``entry != 0``, or ``x < entry`` / ``x <= entry`` (an amount within an allowance)."""
    if _load_key(c) is not None and wanted(_load_key(c)):
        return True
    if c[0] == "not" and c[1][0] == "cmp" and c[1][1] == "eq":
        a, b = c[1][2], c[1][3]
        for side, other in ((a, b), (b, a)):
            entry = _load_key(side)
            if entry is not None and wanted(entry) and other[0] == "const" and other[1] in (0, False):
                return True
    if c[0] == "cmp" and c[1] in ("lt", "le") and _load_key(c[3]) is not None and wanted(_load_key(c[3])):
        return True
    return False


def _held_entry(t: Any, key: Term) -> bool:
    """A stored value read at ``key`` (``_owners[tokenId]``): who holds that key, when compared with the caller."""
    t = _load_key(t)
    return t is not None and key in _keys(t[3]) and not contains(t, IDENTITY_KINDS)


def _holder_is_caller(c: Term, key: Term) -> bool:
    return (
        c[0] == "cmp"
        and c[1] == "eq"
        and ((_is_caller(c[2]) and _held_entry(c[3], key)) or (_is_caller(c[3]) and _held_entry(c[2], key)))
    )


def _granted_by_holder(c: Term, key: Term) -> bool:
    """Requires an entry the holder of ``key`` keeps for the caller to be set (``operatorApprovals[owner][caller]``)."""

    def grant(load: Term) -> bool:
        ks = _keys(load[3])
        return len(ks) >= 2 and _held_entry(ks[0], key) and _is_caller(ks[-1])

    return _requires_truthy(c, grant)


def _granted_by_argument(c: Term, key: Term) -> bool:
    """Requires what an address argument granted the caller to be set (``amount <= allowance[from][caller]``)."""
    if not (key[0] == "arg" and str(key[2]).startswith("address")):
        return False

    def grant(load: Term) -> bool:
        ks = _keys(load[3])
        return len(ks) >= 2 and ks[0] == key and _is_caller(ks[1])

    return _requires_truthy(c, grant)


def _authorized(pc: Term, key: Term) -> bool:
    for c in conjuncts(pc):
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


def _cleared(value: Term) -> bool:
    return value[0] == "const" and value[1] in (0, False)


def var_key(var: Any) -> Any:
    """A storage variable as both reads and writes name it, the same across term tables (a digest for a
    namespaced root or a raw slot, whose terms can be large)."""
    return var if isinstance(var, str) else stable(var)


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


def caller_checked(contract: Any) -> frozenset | None:
    """The storage that any entry point's caller checks read, as (``var_key``, fields): every conjunct of its success
    condition that involves who calls. A write there changes who passes some check, so it is never the caller's own
    business. ``None`` when an entry point can't be lowered: what it checks is unknown."""
    cache = contract.__dict__.setdefault("_psat_caller_checked", {})
    if "vars" in cache:
        return cache["vars"]
    from .lower import Lowerer

    reads: set[tuple] = set()
    out: frozenset | None
    try:
        for fn in contract.functions_entry_points:
            if fn.is_constructor or fn.view or fn.pure:
                continue
            formula = Lowerer(contract).success(fn)
            for conjunct in conjuncts(formula):
                if not contains(conjunct, IDENTITY_KINDS):
                    continue
                reads.update((t[2], t[3]) for t in subterms(conjunct, "load") if t[1] == THIS)
                reads.update(("raw", t[2]) for t in subterms(conjunct, "rawload") if t[1] == THIS)
        found = {(var_key(v), _fields(p) if v != "raw" else ()) for v, p in reads}
        out = frozenset(found)
    except Exception as exc:
        if isinstance(exc, TimeoutError):
            raise
        out = None
    cache["vars"] = out
    return out


def _checked(checked: frozenset, key: tuple) -> bool:
    """Whether a caller check reads what ``key`` writes: the same variable, one field path a prefix of the other
    (a whole struct written, one of its fields read)."""
    var, fields = var_key(key[1]), _fields(key[2])
    return any(v == var and (f[: len(fields)] == fields or fields[: len(f)] == f) for v, f in checked)


def classify(exits: list, lost: bool, function: Any, checked: frozenset | None) -> Scope:
    """``checked``: what ``caller_checked`` gives for the contract (``None``: unknown, so every write is shared)."""
    from .lower import unwritten

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
        debits: dict[tuple, list] = {}
        pending: list[tuple[tuple, Term, Term]] = []
        kept: list[tuple[str, tuple]] = []
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
            old = unwritten(key)
            if value == old:
                continue
            if value[0] == "const" and any(
                c[0] == "cmp" and c[1] == "eq" and {c[2], c[3]} == {old, value} for c in conjuncts(exit_.pc)
            ):
                # Puts back the value this very path requires it to hold (a lock set and reset): no change.
                writes.append(("unchanged", _where(key)))
                continue
            first = next(iter(_keys(key[2])), None)
            own = first is not None and _owned_key(first)
            held = (
                not own and first is not None and not contains(first, IDENTITY_KINDS) and _authorized(exit_.pc, first)
            )
            d = _debit(value, old)
            if (own or held) and (d is not None or _cleared(value)):
                if d is not None:
                    debits.setdefault((key[1], _fields(key[2])), []).append(d)
                kept.append(("own" if own else "authorized", key))
            elif held and not contains(value, frozenset({"load"})) and _credit(value, old, written) is None:
                # What the holder of ``first`` sets on its own entry (an approval, an owner): a replacement, no sum.
                kept.append(("authorized", key))
            else:
                pending.append((key, value, old))
        for key, value, old in pending:
            d = _credit(value, old, written)
            matched = debits.get((key[1], _fields(key[2])), [])
            if d is not None and d in matched:
                matched.remove(d)  # each debit pays for one credit
                kept.append(("credit", key))
            else:
                writes.append(("shared", _where(key)))
        for cls, key in kept:
            if checked is None or _checked(checked, key):
                writes.append(("shared", _where(key)))  # read by some caller check: changes who passes it
            else:
                writes.append((cls, _where(key)))
    out = tuple(sorted(set(writes)))
    if any(cls == "shared" for cls, _ in out):
        return Scope("shared", out)
    return Scope("self" if any(cls != "unchanged" for cls, _ in out) else "none", out)
