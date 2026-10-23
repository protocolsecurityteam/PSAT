"""Whose positions a function's effects touch, read off its lowered writes (see ``SCOPE.md``): ``self`` only when
every write on every way it returns is shown to stay inside entries the caller holds, ``none`` when it writes
nothing, else ``shared``. Whatever can't be shown is shared: a false "shared" costs enumeration time, a false
"self" hides holders."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from .terms import CALLER, FALSE, IDENTITY_KINDS, THIS, Term, conjuncts, contains, stable, subterms

# Inline assembly that acts outside the lowering's view: a call out, code created or destroyed, a delegatecall.
_ASSEMBLY_ACTS = re.compile(r"\b(call|callcode|delegatecall|create|create2|selfdestruct)\s*\(")
# Inline assembly that reads storage the lowering may not place: any check may then read any slot.
_ASSEMBLY_READS = re.compile(r"\bsload\s*\(")


@dataclass(frozen=True)
class Scope:
    kind: str  # "self" | "shared" | "none"
    # (class, where) per write: own, authorized, credit, unchanged, or shared.
    writes: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True)
class Facts:
    """What the whole contract tells about its storage, for classing one function's writes."""

    # (``var_key``, fields) read by any entry point's success condition (its guards, early returns included).
    checked: frozenset = frozenset()
    # Every slot counts as checked: a check reads raw or assembly storage, or an entry point couldn't be lowered.
    everything: bool = True
    # ``var_key`` of what other contracts can read, and so check: public state variables (their getters) and
    # whatever a view or pure entry point reads (``getApproved`` returning ``_tokenApprovals``).
    public: frozenset = frozenset()
    # ``var_key`` of variables some entry point writes keyed first by anything but the caller: an entry
    # ``G[k][caller]`` of any other is set only by ``k``, if at all. ``None``: writes not all known, so none is.
    forgeable: frozenset | None = None


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


def _load(t: Any) -> Any:
    t = _strip(t)
    return t if isinstance(t, tuple) and t[:1] == ("load",) else None


def var_key(var: Any) -> Any:
    """A storage variable as both reads and writes name it, the same across term tables (a digest for a
    namespaced root or a raw slot, whose terms can be large)."""
    return var if isinstance(var, str) else stable(var)


def _truthy(c: Term, wanted: Any) -> bool:
    """Whether condition ``c`` holds only where an entry ``wanted(load)`` picks out is set: the entry itself (a flag),
    ``entry != 0``, or ``x < entry``. ``x <= entry`` is no such proof: ``x`` may be zero."""
    if _load(c) is not None and wanted(_load(c)):
        return True
    if c[0] == "not" and c[1][0] == "cmp" and c[1][1] == "eq":
        a, b = c[1][2], c[1][3]
        for side, other in ((a, b), (b, a)):
            entry = _load(side)
            if entry is not None and wanted(entry) and other[0] == "const" and other[1] in (0, False):
                return True
    return c[0] == "cmp" and c[1] == "lt" and _load(c[3]) is not None and wanted(_load(c[3]))


def _holds(t: Any, key: Term) -> bool:
    """A stored value read at ``key``, its other keys fixed or the caller (``_owners[id]``, ``roles[R][id]``), never
    picked by the caller: who holds ``key``."""
    t = _load(t)
    if t is None or key not in _keys(t[3]):
        return False
    return all(k == key or _is_caller(k) or _strip(k)[0] == "const" for k in _keys(t[3]))


def _holder_is_caller(c: Term, key: Term) -> bool:
    return (
        c[0] == "cmp"
        and c[1] == "eq"
        and ((_is_caller(c[2]) and _holds(c[3], key)) or (_is_caller(c[3]) and _holds(c[2], key)))
    )


def _granted(facts: Facts, var: Any) -> bool:
    return facts.forgeable is not None and var_key(var) not in facts.forgeable


def _granted_by_holder(c: Term, key: Term, facts: Facts) -> bool:
    """Requires the holder of ``key`` to have set an entry for the caller (``operatorApprovals[owner][caller]``)."""

    def grant(load: Term) -> bool:
        ks = _keys(load[3])
        return len(ks) == 2 and _holds(ks[0], key) and _is_caller(ks[1]) and _granted(facts, load[2])

    return _truthy(c, grant)


def _granted_by_argument(c: Term, key: Term, facts: Facts) -> bool:
    """Requires an address argument ``key`` to have granted the caller something (``0 < allowance[from][caller]``)."""
    if not (key[0] == "arg" and str(key[2]).startswith("address")):
        return False

    def grant(load: Term) -> bool:
        ks = _keys(load[3])
        return len(ks) == 2 and ks[0] == key and _is_caller(ks[1]) and _granted(facts, load[2])

    return _truthy(c, grant)


def _authorized(pc: Term, key: Term, facts: Facts) -> bool:
    for c in conjuncts(pc):
        if _holder_is_caller(c, key) or _granted_by_argument(c, key, facts):
            return True
        if c[0] == "or" and any(_holder_is_caller(b, key) for b in c[1]):
            if all(_holder_is_caller(b, key) or _granted_by_holder(b, key, facts) for b in c[1]):
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


def _guarded(pc: Term, d: Term, old: Term) -> bool:
    """The path requires ``d <= old``: a subtraction that can't wrap whatever the arithmetic."""
    for c in conjuncts(pc):
        if c[0] == "cmp" and c[1] == "le" and c[2] == d and c[3] == old:
            return True
        if c[0] == "not" and c[1][0] == "cmp" and c[1][1] == "lt" and c[1][2] == old and c[1][3] == d:
            return True
    return False


def _cleared(value: Term) -> bool:
    return value[0] == "const" and value[1] in (0, False)


def _where(key: tuple) -> str:
    var = key[1]
    name = var if isinstance(var, str) else f"namespaced:{var[-1]}" if isinstance(var, tuple) and var else str(var)
    fields = ".".join(str(f) for f in _fields(key[2]))
    return f"{name}.{fields}" if fields else name


def _nodes(function: Any) -> list | None:
    try:
        return list(function.all_nodes())
    except Exception as exc:
        if isinstance(exc, TimeoutError):
            raise
        return None


def _asm(nodes: list) -> str:
    return "\n".join(str(getattr(n, "inline_asm", "") or "") for n in nodes)


def _checked_arithmetic(function: Any) -> bool:
    """Whether every subtraction ``function`` runs reverts on wrapping: solc 0.8 or later, no ``unchecked`` block."""
    try:
        major, minor = (int(x) for x in str(function.compilation_unit.compiler_version.version).split(".")[:2])
    except Exception as exc:
        if isinstance(exc, TimeoutError):
            raise
        return False
    nodes = _nodes(function)
    return (major, minor) >= (0, 8) and nodes is not None and all(getattr(n.scope, "is_checked", False) for n in nodes)


def _unsigned(contract: Any, var: Any, path: tuple) -> bool:
    """Whether the value at ``var``'s ``path`` is an unsigned integer, read from the declared types."""
    from slither.core.solidity_types import ArrayType, ElementaryType, MappingType, UserDefinedType

    if not isinstance(var, str):
        return False
    declared = next((v for v in contract.state_variables if v.name == var), None)
    type_ = getattr(declared, "type", None)
    for kind, step in path:
        if kind == "k" and isinstance(type_, MappingType):
            type_ = type_.type_to
        elif kind == "k" and isinstance(type_, ArrayType):
            type_ = type_.type
        elif kind == "f" and isinstance(type_, UserDefinedType):
            field = next((e for e in getattr(type_.type, "elems_ordered", ()) if e.name == step), None)
            type_ = getattr(field, "type", None)
        else:
            return False
    return isinstance(type_, ElementaryType) and str(type_).startswith("uint")


def contract_facts(contract: Any) -> Facts:
    """``Facts`` for ``contract``, from every entry point (views, pure functions and the constructor included)."""
    cache = contract.__dict__.setdefault("_psat_scope_facts", {})
    if "facts" in cache:
        return cache["facts"]
    from .lower import Lowerer

    public = {v.name for v in contract.state_variables if v.visibility == "public"}
    facts = Facts(public=frozenset(public))
    try:
        reads: set[tuple] = set()
        forgeable: set = set()
        everything = any(_ASSEMBLY_READS.search(_asm(_nodes(f) or [])) for f in contract.functions)
        writes_known = True
        for fn in contract.functions_entry_points:
            lowerer = Lowerer(contract)
            lowerer.success(fn)
            # Each way it returns, not their union: ``if (blocked[caller]) return;`` leaves ``blocked`` in both
            # paths' conditions and in neither's disjunction (``p or not p``).
            for exit_ in lowerer.exits:
                reads.update((t[2], t[3]) for t in subterms(exit_.pc, "load") if t[1] == THIS)
                everything = everything or bool(subterms(exit_.pc, "rawload"))
                if fn.view or fn.pure:
                    public.update(var_key(t[2]) for t in subterms(exit_.ret or (), "load") if t[1] == THIS)
            writes_known = writes_known and not lowerer.lost
            for exit_ in lowerer.exits:
                for key in exit_.store:
                    if key[0] == "raw":
                        writes_known = False
                    elif key[0] == THIS:
                        first = next(iter(_keys(key[2])), None)
                        if first is None or not _owned_key(first):
                            forgeable.add(var_key(key[1]))
        facts = Facts(
            checked=frozenset((var_key(v), _fields(p)) for v, p in reads),
            everything=everything,
            public=frozenset(public),
            forgeable=frozenset(forgeable) if writes_known else None,
        )
    except Exception as exc:
        if isinstance(exc, TimeoutError):
            raise
    cache["facts"] = facts
    return facts


def _checked(facts: Facts, key: tuple) -> bool:
    """Whether some success condition reads what ``key`` writes: the same variable, one field path a prefix of the
    other (a whole struct written, one of its fields read)."""
    if facts.everything:
        return True
    var, fields = var_key(key[1]), _fields(key[2])
    return any(v == var and (f[: len(fields)] == fields or fields[: len(f)] == f) for v, f in facts.checked)


def classify(exits: list, lost: bool, function: Any, facts: Facts) -> Scope:
    from .lower import unwritten

    contract = getattr(function, "contract", None)
    writes: list[tuple[str, str]] = []
    nodes = _nodes(function) if function is not None else []
    if lost or nodes is None:
        writes.append(("shared", "<writes not followed>"))
    elif _ASSEMBLY_ACTS.search(_asm(nodes)):
        writes.append(("shared", "<assembly call>"))
    wraps = function is None or not _checked_arithmetic(function)
    for exit_ in exits:
        if exit_.pc == FALSE:
            continue
        if subterms(exit_.pc, "delegate") or any(subterms(v, "delegate") for v in exit_.store.values()):
            writes.append(("shared", "<delegatecall>"))
        # (variable, fields, keys after the first) -> amounts debited from the caller's own or held entries there.
        debits: dict[tuple, list] = {}
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
            old = unwritten(key)
            if value == old:
                continue
            if value[0] == "const" and any(
                c[0] == "cmp" and c[1] == "eq" and {c[2], c[3]} == {old, value} for c in conjuncts(exit_.pc)
            ):
                # Puts back the value this very path requires it to hold (a lock set and reset): no change.
                writes.append(("unchanged", _where(key)))
                continue
            if _checked(facts, key):
                writes.append(("shared", _where(key)))  # some check reads it: writing it changes who passes
                continue
            keys = _keys(key[2])
            first = keys[0] if keys else None
            own = first is not None and _owned_key(first)
            held = (
                not own
                and first is not None
                and not contains(first, IDENTITY_KINDS)
                and _authorized(exit_.pc, first, facts)
            )
            d = _debit(value, old)
            decrease = (
                d is not None
                and contract is not None
                and _unsigned(contract, key[1], key[2])
                and (not wraps or _guarded(exit_.pc, d, old))
            )
            public = var_key(key[1]) in facts.public
            if (own or held) and decrease:
                debits.setdefault((var_key(key[1]), _fields(key[2]), tuple(keys[1:])), []).append(d)
                writes.append(("own" if own else "authorized", _where(key)))
            elif (own or held) and not public and _cleared(value):
                writes.append(("own" if own else "authorized", _where(key)))
            elif (
                held
                and not public
                and not contains(value, frozenset({"load"}))
                and _credit(value, old, written) is None
            ):
                # What the holder of ``first`` sets on its own entry (an approval, an owner): a replacement, no sum.
                writes.append(("authorized", _where(key)))
            else:
                pending.append((key, value, old))
        for key, value, old in pending:
            d = _credit(value, old, written)
            keys = _keys(key[2])
            matched = debits.get((var_key(key[1]), _fields(key[2]), tuple(keys[1:])), [])
            if d is not None and d in matched:
                matched.remove(d)  # each debit pays for one credit, at the same keys but the first
                writes.append(("credit", _where(key)))
            else:
                writes.append(("shared", _where(key)))
    out = tuple(sorted(set(writes)))
    if any(cls == "shared" for cls, _ in out):
        return Scope("shared", out)
    return Scope("self" if any(cls != "unchanged" for cls, _ in out) else "none", out)
