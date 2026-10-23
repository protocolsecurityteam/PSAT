"""Who a formula singles out, built from what its identity checks read: a set of addresses per check, combined as
the formula combines them, rather than addresses gathered and asked about one by one.

Each atom is read as the identities that may give it a value (true, or false under a negation), always a superset:

* ``caller == e`` with ``e`` the same for every caller: the one address ``e`` reads.
* ``caller == m[k]`` with ``k`` the caller's to choose: the value each key was last left holding, with its key.
* a condition on the caller's own entries, keyed by it or by a hash of it (``hasRole[r][caller]``,
  ``permissions[keccak256(caller, app, role)]``): when it fails with those entries zero, as for an address nothing
  ever stored, only the identities the logged writes keyed an entry by (or a storage dump accounted for), each with
  the other keys it was set at.
* anything else that involves who calls: every address.

Two sets per part: who may give it the value (``P``), and who may where a stranger doesn't (``S``, see ``_sets``).
A part that doesn't involve the caller treats everyone alike and singles out nobody. When ``S`` of the whole comes
out finite, nobody outside it is singled out: the members are what to read (their entries, at the keys listed) to
know who passes now. The superset rests on every write to each lookup being logged by every implementation the
address has run (``verdict.every``), the history read whole.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .terms import (
    FALSE,
    IDENTITY_KINDS,
    THIS,
    Term,
    contains,
    mk,
    mk_cmp,
    mk_ite,
    replace_terms,
    subterms,
)

_BINDINGS = 64  # argument bindings kept per member; past it, "any" (bindings only steer the search)
_DEPTH = 3  # callees followed into, for a check handed the caller
_WALK_STEPS = 256  # entries followed per linked list kept in a lookup; the walk only names likely members


@dataclass(frozen=True)
class Who:
    """``members``: address -> the argument bindings it may pass under (``({},)`` for any); ``None`` for every
    address but ``excluded``. ``sources``: the lookups and values that listed them."""

    members: dict[int, tuple[dict, ...]] | None
    excluded: frozenset = frozenset()
    sources: frozenset = field(default_factory=frozenset)
    # For everyone (``members`` None): addresses likely among those that matter, drawn from what the chain shows
    # without proof it shows all (a lookup's log words, the code's address constants), and each part's reason it
    # stayed everyone (``storage:roles``, ``arranged``). A finite set is always shown whole.
    hints: frozenset = frozenset()
    why: frozenset = frozenset()
    # The hints as each source named them: the fewer a source names, the likelier its addresses.
    groups: frozenset = frozenset()

    @property
    def finite(self) -> bool:
        return self.members is not None


ANYONE = Who(None)
NOBODY = Who({})


def _anyone(reason: str, hints: Any = frozenset()) -> Who:
    hints = frozenset(hints)
    return Who(None, why=frozenset({reason}), hints=hints, groups=frozenset({hints}) if hints else frozenset())


def _bindings(items: list[dict]) -> tuple[dict, ...]:
    out: list[dict] = []
    for item in items:
        if item not in out:
            out.append(item)
    if not out or len(out) > _BINDINGS or {} in out:
        return ({},)
    return tuple(out)


def _meet(a: Who, b: Who) -> Who:
    sources = a.sources | b.sources
    if a.members is None and b.members is None:
        return Who(None, a.excluded | b.excluded, sources, a.hints | b.hints, a.why | b.why, a.groups | b.groups)
    if a.members is None:
        a, b = b, a
    if b.members is None:
        # Everyone but some meeting a list: the list, shown whole however little is known of the other part.
        return Who({k: v for k, v in a.members.items() if k not in b.excluded}, sources=sources)
    out = {}
    for k in a.members.keys() & b.members.keys():
        joined = [
            {**x, **y} for x in a.members[k] for y in b.members[k] if all(x[t] == y[t] for t in x.keys() & y.keys())
        ]
        if joined:
            out[k] = _bindings(joined)
    return Who(out, sources=sources)


def _join(a: Who, b: Who) -> Who:
    sources = a.sources | b.sources
    if a.members is None and b.members is None:
        return Who(None, a.excluded & b.excluded, sources, a.hints | b.hints, a.why | b.why, a.groups | b.groups)
    if a.members is None:
        a, b = b, a
    if b.members is None:
        # A list joining everyone: everyone, the list's members kept as likely ones.
        listed = frozenset(a.members)
        groups = b.groups | {listed} if listed else b.groups
        return Who(None, b.excluded - a.members.keys(), sources, b.hints | listed, b.why, groups)
    out = dict(a.members)
    for k, v in b.members.items():
        out[k] = _bindings([*out.get(k, ()), *v]) if k in out else v
    return Who(out, sources=sources)


def listed(formula: Term, world: Any, root: str = "caller") -> Who:
    """The identities of ``root`` (``caller``, or ``signer``: whoever signs what any caller hands in) that
    ``formula`` may single out, as a superset (see the module's docstring)."""
    return _sets(formula, world, root)[1]


def _sets(formula: Term, world: Any, root: str = "caller") -> tuple[Who, Who]:
    """Per (sub)formula and the value asked of it, two sets: who may give it that value (``P``), and who may give
    it that value where a stranger, an address nothing names, doesn't (``S``, those it singles out). A part that
    doesn't involve the caller treats everyone alike: its ``S`` is nobody, however its ``P`` comes out.

    Conjunctive (``and`` asked true, ``or`` asked false): ``P = ∩ Pᵢ``, ``S = ∪ⱼ (Sⱼ ∩ ∩ᵢ Pᵢ)``, since where the
    stranger fails the whole it fails some part. Disjunctive: ``P = ∪ Pᵢ``, ``S = ∪ Sᵢ``, since where the stranger
    fails the whole it fails every part."""
    from .decide import FRESH, UNK, Evaluator

    probe = Evaluator(world, {"caller": FRESH, "signer": FRESH})
    memo: dict[tuple, tuple[Who, Who]] = {}
    # The root asked about: for callers, a signer's check is one every caller faces alike, and the reverse.
    kinds = frozenset({"caller", "origin"}) if root == "caller" else frozenset({"signer"})

    def ident(t: Any) -> bool:
        return isinstance(t, tuple) and bool(t) and _strip_conv(t)[0] in kinds

    def conjunctive(parts: list[tuple[Who, Who]]) -> tuple[Who, Who]:
        if not parts:
            return ANYONE, NOBODY
        every = parts[0][0]
        for p, _ in parts[1:]:
            every = _meet(every, p)
        singled = NOBODY
        for _, s in parts:
            singled = _join(singled, _meet(s, every))
        return every, singled

    def disjunctive(parts: list[tuple[Who, Who]]) -> tuple[Who, Who]:
        some, singled = NOBODY, NOBODY
        for p, s in parts:
            some, singled = _join(some, p), _join(singled, s)
        return some, singled

    def walk(t: Term, positive: bool, depth: int) -> tuple[Who, Who]:
        key = (t, positive, depth)
        if key in memo:
            return memo[key]
        memo[key] = (ANYONE, ANYONE)  # while being built: a term met again inside itself stands for anyone
        kind = t[0]
        if kind in ("and", "or"):
            parts = [walk(x, positive, depth) for x in t[1]]
            out = conjunctive(parts) if (kind == "and") == positive else disjunctive(parts)
        elif kind == "not":
            out = walk(t[1], not positive, depth)
        elif kind == "ite":
            c, a, b = t[1], t[2], t[3]
            out = disjunctive(
                [
                    conjunctive([walk(c, True, depth), walk(a, positive, depth)]),
                    conjunctive([walk(c, False, depth), walk(b, positive, depth)]),
                ]
            )
        elif kind == "const":
            out = (ANYONE if bool(t[1]) == positive else NOBODY), NOBODY
        elif not contains(t, kinds):
            # What every caller faces alike singles out nobody; one the code can never flip back (a configured
            # flag, a consumed initializer) reads as it is, in every state asked about.
            value = probe.truth(t) if t in world.latched else _by_code(t)
            out = (ANYONE if value is UNK or value is positive else NOBODY), NOBODY
        else:
            out = atom(t, positive, depth)
        memo[key] = out
        return out

    def _by_code(t: Term) -> Any:
        """A call's success its callee's code settles at this block (a function the callee doesn't have): what it
        is, in every state asked about; else unknown."""
        if t[0] in ("ok", "caught") and isinstance(t[1], tuple) and t[1] and t[1][0] == "call":
            lowered = world.callee(t[1])
            if lowered is not None and lowered[0] == FALSE:
                return t[0] == "caught"
        return UNK

    def leaf(t: Term, positive: bool, may: Who) -> tuple[Who, Who]:
        """An atom's two sets: whoever may give it the value, singled out unless a stranger surely gives it too."""
        stranger = probe.truth(t)
        return may, (NOBODY if stranger is positive else may)

    def atom(t: Term, positive: bool, depth: int) -> tuple[Who, Who]:
        if t in world.arranged:
            # The caller's own entries, which open code lets anyone bring about.
            guess = _unproven({**_logged_words(THIS), **_named_members()}, "arranged")
            return guess, guess
        if t[0] == "cmp":
            for i in (2, 3):
                if t[i][0] == "ite" and contains(t[i], kinds):
                    # ``(c ? who : 0) == admin``: one comparison per branch.
                    c, a, b = t[i][1], t[i][2], t[i][3]
                    pick = (lambda x: (t[1], x, t[3])) if i == 2 else (lambda x: (t[1], t[2], x))
                    return walk(mk_ite(c, mk_cmp(*pick(a)), mk_cmp(*pick(b))), positive, depth)
        if t[0] == "cmp" and t[1] == "eq":
            for side, other in ((t[2], t[3]), (t[3], t[2])):
                if ident(side) and not contains(other, IDENTITY_KINDS):
                    return leaf(t, positive, equal(other, positive))
        found = entries_of(t, positive)
        if found is not None:
            return leaf(t, positive, found)
        calls = [c for c in subterms(t, "call") if any(contains(a, kinds) for a in c[3])]
        if calls and depth < _DEPTH:
            # A check handed the caller (``acl.hasRole(role, msg.sender)``): what the callee returns, in this
            # call's terms, in the call's place.
            returned: dict = {}
            for c in calls:
                lowered = world.callee(c)
                # Whether it returns is its callee's condition (``ok``, ``caught``); what it returns, its values.
                asked = (
                    {x: lowered[0] if x[0] == "ok" else mk("not", lowered[0]) for x in _asked(t, c)} if lowered else {}
                )
                items = {
                    x: lowered[1][x[2]] for x in subterms(t, "item") if x[1] == c and lowered and x[2] < len(lowered[1])
                }
                bare = c in subterms(replace_terms(t, {**asked, **items}), "call")
                if lowered is None or (bare and not lowered[1]):
                    # Code not followed: the addresses this code names, unproven to be all it lets through.
                    guess = _unproven({**_logged_words(c[1], THIS), **_named_members()}, f"call:{c[2]}")
                    return guess, guess
                returned.update(asked)
                returned.update(items)
                if bare:
                    returned[c] = lowered[1][0]
            return walk(replace_terms(t, returned), positive, depth + 1)
        # What the writers of each lookup it keys by the caller logged (a check followed into a manager: the
        # manager's grants), and the logs of every contract it reads.
        from .decide import _named_lookup, _unlisted

        found: set[int] = set()
        loads = subterms(t, "load")
        for x in loads:
            if any(contains(k, kinds) for kind, k in x[3] if kind == "k"):
                found |= _unlisted(world, x[1], _named_lookup(x[2], x[3])[0])[0]
        read = sorted({x[1] for kind in ("load", "rawload") for x in subterms(t, kind)}, key=repr)
        members = {**{m % 2**160: ({},) for m in found}, **_logged_words(THIS, *read), **_named_members()}
        guess = _unproven(members, "identity_use")
        return guess, guess

    named: list = []
    t_atom: list = [None]  # the atom ``entries_of`` is reading
    sampled: list = [False]  # whether a contract's log words were read partial: hints drawn from a sample

    def _named_members() -> dict[int, tuple[dict, ...]]:
        """The addresses the code names (``World.named``)."""
        if not named:
            named.append({a % 2**160: ({},) for a in world.named})
        return named[0]

    def _logged_words(*places: Any) -> dict[int, tuple[dict, ...]]:
        """The address-shaped words of every log these contracts recorded: where the code names no holder, the
        likely ones (a pauser kept in another contract, granted by its events)."""
        out: dict[int, tuple[dict, ...]] = {}
        for place in places:
            address = probe.eval(place)
            if isinstance(address, int) and not isinstance(address, bool):
                words = world.chain.all_log_words(address % 2**160)
                out.update({w: ({},) for w in words if 2**150 <= w < 2**160})
                sampled[0] = sampled[0] or address % 2**160 in world.chain.truncated
        return out

    def _unproven(members: Any, reason: str) -> Who:
        """Everyone, as far as is shown, with ``members`` the likely ones."""
        found = _anyone(reason, {m % 2**160 for m in members})
        if sampled[0]:
            found = Who(None, found.excluded, found.sources, found.hints, found.why | {"history_truncated"}, found.groups)
        return found

    def _walked(x: Term, keys: list) -> set[int]:
        """A list kept in the lookup itself (Safe's ``owners[SENTINEL] -> owner -> ... -> SENTINEL``): the entries
        followed from each small constant the condition names, as likely members."""
        from .decide import _LOWEST_SENDER

        if len(keys) != 1:
            return set()
        starts = {c[1] for c in subterms(t_atom[0], "const") if type(c[1]) is int and 0 < c[1] < _LOWEST_SENDER}
        out: set[int] = set()
        for start in sorted(starts | {1}):
            at = start
            for _ in range(_WALK_STEPS):
                entry = replace_terms(x, {keys[0]: mk("const", at, "address")})
                value = probe.eval(entry)
                if not isinstance(value, int) or isinstance(value, bool) or value < _LOWEST_SENDER or value in out:
                    break
                out.add(value % 2**160)
                at = value
        return out

    def equal(other: Term, positive: bool) -> Who:
        stripped = _strip_conv(other)
        if not contains(other, _CHOSEN):
            value = probe.eval(other)
            if not isinstance(value, int) or isinstance(value, bool):
                return _unproven(_named_members(), "unread_identity")  # whoever it holds goes unlisted
            who = value % 2**160
            return Who({who: ({},)}, sources=frozenset({("value", other)})) if positive else Who(None, frozenset({who}))
        if positive and stripped[0] == "load" and not contains(stripped, IDENTITY_KINDS):
            # ``caller == pools[pool].manager``, ``pool`` the caller's: the value each entry was last left holding.
            from .decide import _caller_chosen, _named_lookup

            var, path = _named_lookup(stripped[2], stripped[3])
            keys = [step for kind, step in path if kind == "k"]
            chosen = [k for k in keys if k[0] == "arg" and _caller_chosen(k)]
            address = probe.eval(stripped[1])
            if len(keys) == 1 and len(chosen) == 1 and isinstance(address, int) and not isinstance(address, bool):
                fields = tuple(step for kind, step in path if kind == "f")
                latest = world.latest(address, var, fields)
                if latest is not None:
                    members: dict[int, list[dict]] = {}
                    for k, value in latest.items():
                        members.setdefault(value % 2**160, []).append({chosen[0]: k})
                    return Who({w: _bindings(b) for w, b in members.items()}, sources=frozenset({("lookup", var)}))
        if stripped[0] == "load" and not contains(stripped, IDENTITY_KINDS):
            # A stored value at keys the caller picks, its every value not shown: whoever its writers' logs name.
            from .decide import _named_lookup, _unlisted

            found, _ = _unlisted(world, stripped[1], _named_lookup(stripped[2], stripped[3])[0])
            return _unproven({**{m % 2**160: ({},) for m in found}, **_named_members()}, "chosen_identity")
        return _unproven(_named_members(), "chosen_identity")  # compared with what the caller sends (``from``)

    def entries_of(t: Term, positive: bool) -> Who | None:
        """For a condition whose every mention of the caller keys an entry (as the key, or a part hashed into it):
        those the logged writes keyed, when the condition, with the caller's entries zero, goes the other way for
        anyone."""
        from .decide import ANY_KEY, _caller_chosen, _named_lookup

        def keyed(k: Term) -> tuple[int, ...] | None:
            """Where the caller is in a key: ``()`` for the key itself, ``(j,)`` for the ``j``-th part hashed in."""
            if ident(k):
                return ()
            if k[0] == "hash":
                parts = _hash_parts(k)
                at = [j for j, x in enumerate(parts) if ident(x)]
                if len(at) == 1 and not any(contains(x, kinds) for j, x in enumerate(parts) if j != at[0]):
                    return (at[0],)
            return None

        t_atom[0] = t
        loads = [x for x in subterms(t, "load") if any(keyed(k) is not None for kind, k in x[3] if kind == "k")]
        if not loads:
            return None
        zero = replace_terms(t, {x: mk("const", 0, "uint256") for x in loads})
        if contains(zero, kinds):
            return None  # the caller there otherwise too
        answer = Evaluator(world, {"caller": FRESH, "signer": FRESH}).truth(zero)
        if answer is UNK or answer is positive:
            # An address nothing stored may pass it too (a balance at least the amount): the likely ones are those
            # the lookups' writers logged.
            from .decide import _unlisted

            found = set()
            for x in loads:
                found |= _unlisted(world, x[1], _named_lookup(x[2], x[3])[0])[0]
            return _unproven({**{m % 2**160: ({},) for m in found}, **_named_members()}, "holdings")
        out = NOBODY
        for x in loads:
            var, path = _named_lookup(x[2], x[3])
            keys = [step for kind, step in path if kind == "k"]
            fields = tuple(step for kind, step in path if kind == "f")
            at = [(i, keyed(k)) for i, k in enumerate(keys) if keyed(k) is not None]
            address = probe.eval(x[1])
            if len(at) != 1 or not isinstance(address, int) or isinstance(address, bool):
                return _unproven(_named_members(), "unplaced_lookup")
            ((i_who, part),) = at
            rows = world.entries(x[1], var, len(keys), fields)
            if rows is None:
                dumped = world.dumped
                if dumped and (
                    (x[1], x[2]) in dumped["lookups"]
                    or (x[1], var) in dumped["lookups"]
                    or address in dumped["addresses"]
                ):
                    # A storage dump accounted for this lookup: whoever may pass through it is among these.
                    out = _join(
                        out, Who({w % 2**160: ({},) for w in dumped["members"]}, sources=frozenset({("dump", var)}))
                    )
                    continue
                # Not listed whole: whoever its writers' logs and the code name, unproven to be all.
                from .decide import _unlisted

                found, reason = _unlisted(world, x[1], var)
                found = found | _walked(x, keys)
                out = _join(out, _unproven({**{m % 2**160: ({},) for m in found}, **_named_members()}, reason))
                continue
            fixed: dict[tuple, int] = {}  # (key, part or None) -> the word it must be
            among: dict[tuple, frozenset] = {}  # (key, part or None) -> the words it may be
            chosen: dict[tuple, Term] = {}
            for i, k in enumerate(keys):
                pieces = [(None, k)] if k[0] != "hash" or i != i_who else list(enumerate(_hash_parts(k)))
                for j, piece in pieces:
                    if (i == i_who and j == (part[0] if part else None)) or contains(piece, IDENTITY_KINDS):
                        continue
                    if piece[0] == "arg" and _caller_chosen(piece):
                        chosen[(i, j)] = piece
                    elif _strip_conv(piece)[0] == "load" and not contains(piece, IDENTITY_KINDS):
                        # A key read from storage at keys the caller picks (``_roles[role].adminRole``): only a value
                        # that field has ever held, when its every value is logged.
                        stored = _strip_conv(piece)
                        named, steps = _named_lookup(stored[2], stored[3])
                        held = world.values_of(
                            stored[1],
                            named,
                            sum(1 for kind, _ in steps if kind == "k"),
                            tuple(step for kind, step in steps if kind == "f"),
                        )
                        if held is not None and contains(piece, _CHOSEN):
                            among[(i, j)] = frozenset(v % 2**256 for v in held)
                        elif not contains(piece, _CHOSEN):
                            value = probe.eval(piece)
                            if isinstance(value, int) and not isinstance(value, bool):
                                fixed[(i, j)] = value % 2**256
                    elif not contains(piece, _CHOSEN):
                        value = probe.eval(piece)
                        if isinstance(value, int) and not isinstance(value, bool):
                            fixed[(i, j)] = value % 2**256
            members: dict[int, list[dict]] = {}
            for row in rows:
                cell = row[i_who]
                if cell is ANY_KEY:
                    continue  # a constructor's key placed elsewhere in it: the row that places it here lists it
                if part and not isinstance(cell, tuple):
                    # The event named the hash, not its parts: whose it is goes unread.
                    return _unproven(_named_members(), "hashed_key")
                who = cell[part[0]] if part else cell

                def word(i: int, j: Any) -> Any:
                    value = row[i]
                    return value[j] if j is not None and isinstance(value, tuple) else value

                if any(
                    word(i, j) != v
                    for (i, j), v in fixed.items()
                    if not (j is not None and not isinstance(row[i], tuple)) and row[i] is not ANY_KEY
                ):
                    continue
                if any(word(i, j) not in words for (i, j), words in among.items() if row[i] is not ANY_KEY):
                    continue
                binding = {
                    piece: word(i, j) for (i, j), piece in chosen.items() if _one_word(piece) and row[i] is not ANY_KEY
                }
                members.setdefault(who % 2**160, []).append(binding)
            out = _join(out, Who({w: _bindings(b) for w, b in members.items()}, sources=frozenset({("lookup", var)})))
        return out

    return walk(formula, True, 0)


_CHOSEN = frozenset({"arg", "len", "elem", "callvalue", "calldatasize"})


def _asked(t: Term, call: Term) -> list:
    """The ``ok``/``caught`` terms in ``t`` asking whether ``call`` returns."""
    return [x for kind in ("ok", "caught") for x in subterms(t, kind) if x[1] == call]


def _hash_parts(key: Term) -> list:
    """A hashed key's inputs, an encoding's items in its place (``keccak256(abi.encode(who, data))``)."""
    return [_strip_conv(x) for i in key[2] for x in (i[2] if isinstance(i, tuple) and i[0] == "enc" else (i,))]


def _one_word(arg: Term) -> bool:
    """An argument whose value is the one word an event logs for it (not a dynamic value, whose topic is its hash)."""
    type_ = arg[2] if len(arg) > 2 else ""
    return isinstance(type_, str) and not (type_ in ("bytes", "string") or "[" in type_ or type_.startswith("("))


def _strip_conv(t: Term) -> Term:
    while t[0] == "conv":
        t = t[2]
    return t
