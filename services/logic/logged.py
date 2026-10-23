"""Whether every write to a lookup is logged: what lets a lookup's events list everyone it holds.

Each entry point and constructor is lowered with its events as marks among its writes (``lower``). A write that can
leave an entry of the lookup nonzero is logged when, wherever it is made, an event names each of its keys: the key
itself, or for a key hashed from parts (``keccak256(abi.encode(caller, target, data))``, a raw slot hashed from a seed,
a role and a holder) every part that isn't a constant. A write that can only clear an entry needs no event: listing
someone no longer there costs a question, not a member.

Storage the lowering can't follow (code it didn't run, assembly it couldn't read, a delegatecall into code the
contract keeps) proves nothing. A delegatecall into code the caller names (an upgrade) is that function's own power,
as in ``verdict._written_values``.
"""

from __future__ import annotations

from typing import Any

from .terms import FALSE, THIS, TRUE, Term, mk, mk_and, mk_not, mk_or, packed_width, term_epoch

_NONE = object()


def _entries(contract: Any) -> list[tuple[Term, dict, int | None]] | None:
    """(path condition, writes and event marks, the function's selector) per way each entry point or constructor
    returns; ``None`` when one can't be lowered whole."""
    from eth_utils.crypto import keccak

    from .lower import Lowerer
    from .verdict import _delegates, _own_code

    cache = contract.__dict__.setdefault("_psat_logged", {})
    if cache.get("epoch") != term_epoch():
        cache.clear()
        cache["epoch"] = term_epoch()
    if "entries" not in cache:
        entries: list | None = []
        functions = [
            f
            for f in contract.functions
            if (f.is_constructor or f in contract.functions_entry_points) and not (f.view or f.pure)
        ]
        for fn in functions:
            try:
                lowerer = Lowerer(contract)
                lowerer.success(fn)
            except Exception as exc:
                if isinstance(exc, TimeoutError):
                    raise
                entries = None
                break
            selector = None if fn.is_constructor else int.from_bytes(keccak(text=fn.solidity_signature)[:4], "big")
            exits = [(e.pc, e.store, selector) for e in lowerer.exits]
            # A delegatecall into code the caller names (``execute(target, data)``) may write any entry, logged or
            # not: no lookup of the contract is listed whole by its events.
            if lowerer.lost or any(not _own_code(d) for pc, store, _ in exits for d in _delegates(pc, store)):
                entries = None
                break
            entries.extend(exits)
        cache["entries"] = entries
    return cache["entries"]


def logged(
    contract: Any, var: Any, keys: int, fields: tuple, hashed: bool, valued: bool = False, constructors: bool = True
) -> frozenset[str] | None:
    """The events that name the keys of every write that can set an entry of ``var`` (read under ``keys`` keys and
    ``fields``), by bare name and arity; ``None`` unless every such write is logged. A write above the entries (the
    whole mapping) names none of them, so it counts only when it clears. ``hashed``: the lookup is read at a key
    hashed from the identity, so a hashed key counts only through its parts, never as the hash itself.
    ``constructors=False``: the constructor's writes left out (listed another way, ``snapshot.creation_keys``)."""
    answers = contract.__dict__.setdefault("_psat_logged_answers", {})
    query = ("named", repr(var), keys, tuple(fields), hashed, valued, constructors)
    if query in answers:
        return answers[query]
    _spent["left"] = contract.__dict__.get("_psat_propositional_left", _PROPOSITIONAL_SECONDS)
    try:
        return _logged(contract, var, keys, fields, hashed, valued, answers, query, constructors)
    finally:
        contract.__dict__["_psat_propositional_left"] = _spent["left"]
        _spent["left"] = _PROPOSITIONAL_SECONDS


def _logged(
    contract: Any,
    var: Any,
    keys: int,
    fields: tuple,
    hashed: bool,
    valued: bool,
    answers: dict,
    query: tuple,
    constructors: bool = True,
):
    from .decide import _named_lookup
    from .verdict import _spec_name

    entries = _entries(contract)
    found: set | None = None if entries is None else set()
    lists: dict = contract.__dict__.setdefault("_psat_logged_lists", {})
    if lists.get("epoch") != term_epoch():
        lists.clear()
        lists["epoch"] = term_epoch()
    closed = lambda key: _from_list(key, entries or [], lists)  # noqa: E731
    for pc, store, selector in entries or ():
        if selector is None and not constructors:
            continue
        for loc, value in store.items():
            if loc[0] == "raw" and loc[1] == THIS and _may_be_entry(loc[2]):
                if _sets(value, mk("rawload", THIS, loc[2])) != FALSE:
                    found = None  # assembly writing where some mapping's entry may be, unlogged as that entry
                    break
                continue
            if loc[0] != THIS:
                continue
            name, path = _named_lookup(loc[1], loc[2])
            if _spec_name(name) != var:
                continue
            wrote = tuple(step for kind, step in path if kind == "f")
            if wrote[: len(fields)] != fields[: len(wrote)]:
                continue  # another member of the same entry (a role's admin beside its members)
            written = [step for kind, step in path if kind == "k"]
            old = mk("load", *loc)
            if valued and len(wrote) < len(fields):
                # The whole struct written (``_streams[id] = Stream(...)``): the value is the field read.
                from .verdict import _field

                for step in fields[len(wrote) :]:
                    value, old = _field(value, step), mk("load", loc[0], loc[1], (*loc[2], ("f", step)))
            if len(written) < keys:
                events = set() if _sets(value, old) == FALSE else None
            else:
                events = _logging(pc, store, selector, value, old, written, hashed, valued, closed)
            if events is None:
                found = None
                break
            found |= events
        if found is None:
            break
    answers[query] = None if found is None else frozenset(found)
    return answers[query]


def _declarations(contract: Any) -> dict[tuple, list]:
    """(name, arity) -> the distinct declarations an emission of that shape may be: one event declared in an
    interface and seen again through the contract inheriting it is one, by its ABI signature and indexed places."""
    from slither.utils.type import convert_type_for_solidity_signature_to_string

    from .verdict import _declared_events

    out: dict[tuple, dict] = {}
    for event in _declared_events(contract):
        shape = (
            ",".join(convert_type_for_solidity_signature_to_string(e.type) for e in event.elems),
            tuple(bool(e.indexed) for e in event.elems),
        )
        out.setdefault((event.name, len(event.elems)), {}).setdefault(shape, event)
    return {k: list(v.values()) for k, v in out.items()}


def _place(key: Any, args: tuple) -> tuple | None:
    """Where an event names ``key``: ``("is", value)`` for a constant, ``("at", i)`` for its one argument."""
    # Where the event names it, a constant too (so every write the event logs reads it from the same place);
    # else a constant the write fixes.
    where = [i for i, a in enumerate(args) if _strip(a) == key]
    if len(where) == 1:
        return ("at", where[0])
    if _constant(key) and key[0] == "const" and isinstance(key[1], (int, str, bytes)):
        return ("is", key[1])  # a part the write fixes (a role, a salt like ``"PERMISSION"``)
    return None


def _readable(declaration: Any, places: tuple) -> bool:
    """Whether each argument placed is read back as one word where ``verdict._event_args`` looks: an indexed one of
    a one-word type, or a one-word one in the data with only one-word heads before it (a dynamic one's head is an
    offset, a static array's several words)."""
    from slither.utils.type import convert_type_for_solidity_signature_to_string

    def text(e: Any) -> str:
        return convert_type_for_solidity_signature_to_string(e.type)

    def word(e: Any) -> bool:
        return "[" not in text(e) and not text(e).startswith("(") and text(e) not in ("bytes", "string")

    def head(e: Any) -> bool:
        return word(e) or text(e) in ("bytes", "string") or text(e).endswith("[]")

    elems = declaration.elems
    used = [p for kind, p in places if kind == "at"]
    used += [p for kind, parts in places if kind == "parts" for k, p in parts if k == "at"]
    for i in used:
        if i >= len(elems) or not word(elems[i]):
            return False
        if not elems[i].indexed and not all(head(e) for e in elems[:i] if not e.indexed):
            return False
    return True


def written_by(contract: Any, var: Any, fields: tuple) -> list[dict] | None:
    """Where the events that log ``var``'s writes (a lookup under one key, at ``fields``) name the key and the value
    left, as the writer specs ``verdict`` replays: signature, indexed positions, key and value positions. Read from
    the lowering itself, so writes made in a library on a ``storage`` pointer count (Lido CSM's ``NodeOperatorOps``).
    ``None`` unless every write that can set an entry is logged with both, and every emission of each event chosen
    comes with such a write, naming them at the same places."""
    from .decide import _named_lookup
    from .verdict import _spec_name

    answers = contract.__dict__.setdefault("_psat_logged_answers", {})
    query = ("written_by", repr(var), tuple(fields))
    if query in answers:
        return answers[query]
    answers[query] = None
    entries = _entries(contract)
    if entries is None or logged(contract, var, 1, fields, False, True) is None:
        return None
    declared = _declarations(contract)
    writes = []  # per write that can set an entry: (store, key, value, sets)
    for pc, store, selector in entries:
        for loc, value in store.items():
            if loc[0] != THIS:
                continue
            name, path = _named_lookup(loc[1], loc[2])
            if _spec_name(name) != var:
                continue
            wrote = tuple(step for kind, step in path if kind == "f")
            if wrote[: len(fields)] != fields[: len(wrote)]:
                continue
            keys = [step for kind, step in path if kind == "k"]
            old = mk("load", *loc)
            if len(wrote) < len(fields):
                from .verdict import _field

                for step in fields[len(wrote) :]:
                    value, old = _field(value, step), mk("load", loc[0], loc[1], (*loc[2], ("f", step)))
            sets = _sets(value, old)
            if sets == FALSE:
                continue  # only clears: what was there is no longer anyone's, nothing to replay
            if len(keys) != 1:
                return None
            # The value it leaves: the whole term, or the one value it sets where it isn't what was there
            # (``if (new != old) m[k].manager = new``).
            left = [_strip(v) for v in _set_values(value, old)]
            writes.append((store, _strip(keys[0]), left[0] if len(left) == 1 else _strip(value), sets))
    if not writes:
        answers[query] = []
        return []  # never set: no value to replay

    def placed(args: tuple, key: Term, value: Term) -> tuple | None:
        at_key = [i for i, a in enumerate(args) if _strip(a) == key]
        at_value = [i for i, a in enumerate(args) if _strip(a) == value]
        return (at_key[0], at_value[0]) if len(at_key) == 1 and len(at_value) == 1 else None

    # Per event, the places every write it logs names the key and value at; a write its emission can't be told
    # from (two places, none) rules the event out.
    places: dict[tuple, set] = {}
    covered = [set() for _ in writes]
    for i, (store, key, value, sets) in enumerate(writes):
        for mark, made in store.items():
            if mark[0] != "emit" or mark[1].startswith("log"):
                continue
            event = (mark[1], len(mark[2]))
            where = placed(mark[2], key, value)
            if where is None or not (_implies(sets, made) or _implies_as_logic(sets, made)):
                continue
            places.setdefault(event, set()).add(where)
            covered[i].add(event)
    usable = {
        e
        for e, at in places.items()
        if len(at) == 1
        and len(declared.get(e, ())) == 1
        and _readable(declared[e][0], tuple(("at", i) for i in next(iter(at))))
    }
    # An emission of one with no such write on its path (a manager changed elsewhere) would replay a value never left.
    for _, store, _ in entries:
        for mark in store:
            if mark[0] != "emit" or (mark[1], len(mark[2])) not in usable:
                continue
            key_at, value_at = next(iter(places[(mark[1], len(mark[2]))]))
            key, value = _strip(mark[2][key_at]), _strip(mark[2][value_at])
            if not any(w[0] is store and w[1] == key and w[2] == value for w in writes):
                usable.discard((mark[1], len(mark[2])))
    if any(not (c & usable) for c in covered):
        return None
    from slither.utils.type import convert_type_for_solidity_signature_to_string

    specs = []
    for event in sorted(usable):
        (declaration,) = declared[event]
        key_at, value_at = next(iter(places[event]))
        types = ",".join(convert_type_for_solidity_signature_to_string(e.type) for e in declaration.elems)
        specs.append(
            {
                "mapping_name": var,
                "member_path": list(fields),
                "event_signature": f"{declaration.name}({types})",
                "indexed_positions": [i for i, e in enumerate(declaration.elems) if e.indexed],
                "key_position": key_at,
                "key_positions_by_index": {0: key_at},
                "value_position": value_at,
            }
        )
    answers[query] = specs
    return specs


def keyed_by(
    contract: Any, var: Any, keys: int, fields: tuple, constructors: bool = True, whole: bool = True
) -> list[dict] | None:
    """Where the events that log ``var``'s writes (read under ``keys`` keys, at ``fields``) name each key, so that
    their history lists every key tuple an entry was ever set at: per event, its signature, indexed positions and
    the place of each key (``("at", position)``, or ``("is", value)`` for a key the write fixes, a role constant).
    ``None`` unless every write that can set an entry has such an event on its path. An emission that comes with
    no such write lists a tuple never set: one more to read, never one missed. ``whole=False``: the events of the
    writes that do log their keys, however many don't, for keys to try only."""
    from .decide import _named_lookup
    from .verdict import _spec_name

    answers = contract.__dict__.setdefault("_psat_logged_answers", {})
    query = ("keyed_by", repr(var), keys, tuple(fields), constructors, whole)
    if query in answers:
        return answers[query]
    answers[query] = None
    entries = _entries(contract)
    # Asked as for a hashed key, which counts only through its parts; a plain key the same either way.
    if entries is None or (whole and logged(contract, var, keys, fields, True, constructors=constructors) is None):
        return None
    declared = _declarations(contract)
    places: dict[tuple, set] = {}
    covered: list[set] = []
    for pc, store, selector in entries:
        if selector is None and not constructors:
            continue
        for loc, value in store.items():
            if loc[0] != THIS:
                continue
            name, path = _named_lookup(loc[1], loc[2])
            if _spec_name(name) != var:
                continue
            wrote = tuple(step for kind, step in path if kind == "f")
            if wrote[: len(fields)] != fields[: len(wrote)]:
                continue
            written = [_strip(step) for kind, step in path if kind == "k"]
            sets = _sets(value, mk("load", *loc))
            if sets == FALSE:
                continue
            if len(written) != keys:
                if not whole:
                    continue
                return None
            events = set()
            for mark, made in store.items():
                if mark[0] != "emit":
                    continue
                args = mark[2]
                if mark[1] in ("log1", "log2", "log3", "log4"):
                    # Assembly's own log (DSS's ``note``): read back by its first topic, the rest topics too.
                    first = _strip(args[0]) if args else None
                    if first == mk("sig") and selector is not None:
                        event = ("topic0", selector << 224, len(args) - 1)
                    elif first is not None and first[0] == "const" and isinstance(first[1], int):
                        event = ("topic0", first[1], len(args) - 1)
                    else:
                        continue
                    args = args[1:]
                else:
                    event = (mark[1], len(args))
                at = []
                for key in written:
                    place = _place(key, args)
                    if place is None and isinstance(key, tuple) and key[0] == "hash":
                        # A key hashed from parts (``keccak256(abi.encode(who, data))``): each part placed.
                        parts = [_place(_strip(x), args) for x in _inputs(key)]
                        place = ("parts", tuple(parts)) if all(p is not None for p in parts) else None
                    if place is None:
                        break
                    at.append(place)
                if len(at) != len(written) or not (_implies(sets, made) or _implies_as_logic(sets, made)):
                    continue
                places.setdefault(event, set()).add(tuple(at))
                events.add(event)
            covered.append(events)
    usable = {
        e
        for e, at in places.items()
        if len(at) == 1
        and (e[0] == "topic0" or (len(declared.get(e, ())) == 1 and _readable(declared[e][0], next(iter(at)))))
    }
    if not covered:
        answers[query] = []
        return []  # never set: no entry to list
    if whole and any(not (c & usable) for c in covered):
        return None
    from slither.utils.type import convert_type_for_solidity_signature_to_string

    specs = []
    for event in sorted(usable, key=repr):
        if event[0] == "topic0":
            specs.append(
                {
                    "event_signature": None,
                    "topic0": event[1],
                    "indexed_positions": list(range(event[2])),
                    "keys": next(iter(places[event])),
                }
            )
            continue
        (declaration,) = declared[event]
        types = ",".join(convert_type_for_solidity_signature_to_string(e.type) for e in declaration.elems)
        specs.append(
            {
                "event_signature": f"{declaration.name}({types})",
                "indexed_positions": [i for i, e in enumerate(declaration.elems) if e.indexed],
                "keys": next(iter(places[event])),
            }
        )
    answers[query] = specs
    return specs


def members(contract: Any, var: Any) -> list[tuple]:
    """The members of ``var`` its writes reach, as field paths: every prefix of each write's fields
    (``_proposers.executors``, ``_members._inner`` and ``_members._inner._positions``)."""
    from .decide import _named_lookup
    from .verdict import _spec_name

    out: set = set()
    for _, store, _ in _entries(contract) or ():
        for loc in store:
            if loc[0] != THIS:
                continue
            name, path = _named_lookup(loc[1], loc[2])
            fields = tuple(step for kind, step in path if kind == "f")
            if _spec_name(name) == var:
                out.update(fields[: i + 1] for i in range(len(fields)))
    return sorted(out, key=repr)


def logged_raw(contract: Any, slot: Term) -> frozenset[str] | None:
    """``logged`` for a raw slot hashed from the identity (``sload(keccak256(seed, role, holder))``): every raw write
    that may land on a slot of that shape (the same number of parts, the same constants in the same places) logs its
    parts. A write to a slot of another shape can't land there; one at a slot of no known shape might."""
    shape = _shape(slot)
    if shape is None or (len(shape) == 2 and shape[1] is not None):
        return None  # ``keccak256(key . n)``: a named mapping's slot too
    answers = contract.__dict__.setdefault("_psat_logged_answers", {})
    query = ("raw", shape)
    if query in answers:
        return answers[query]
    entries = _entries(contract)
    found: set | None = None if entries is None else set()
    for pc, store, selector in entries or ():
        for loc, value in store.items():
            if loc[0] != "raw" or loc[1] != THIS:
                continue
            target = loc[2]
            if _constant(target) or _offset_of_hash(target):
                continue
            other = _shape(target)
            if other is not None and other != shape:
                continue
            if other is None:
                found = None
                break
            events = _logging(pc, store, selector, value, mk("rawload", THIS, target), [target], True)
            if events is None:
                found = None
                break
            found |= events
        if found is None:
            break
    answers[query] = None if found is None else frozenset(found)
    return answers[query]


def _logging(
    pc: Term,
    store: dict,
    selector: int | None,
    value: Term,
    old: Term,
    keys: list,
    hashed: bool,
    valued: bool = False,
    closed: Any = None,
) -> set | None:
    """The events on this path that name every key of a write of ``value`` over ``old`` whenever it can leave the
    entry set, as (name, arity) for a declared event or ("topic0", topic, topic count) for one written in assembly;
    an empty set for a write that only clears; ``None`` when no event does. ``valued``: the value written must be
    named too (``delegates[voter] = delegate`` read back as whoever it names)."""
    sets = _sets(value, old)
    if sets == FALSE or (all(_constant(k) for k in keys) and not valued):
        return set()  # an entry only cleared, or one at a fixed place, read there directly: nothing to list
    # The value left: named whole (an event of the local holding ``a == 0 ? from : a``), or each value it may be.
    values = [v for v in _set_values(value, old) if not _constant(v)] if valued else []
    # A key taken from a list every write of which logs what it adds (an EnumerableSet's values, re-indexed on a
    # remove): already named, by the events that added it.
    listed = {i: closed(k) for i, k in enumerate(keys)} if closed is not None else {}
    if listed and all(v is not None for v in listed.values()) and not values:
        return set().union(*listed.values())
    keys = [k for i, k in enumerate(keys) if listed.get(i) is None]
    out = set()
    for mark, made in store.items():
        if mark[0] != "emit":
            continue
        name, args = mark[1], mark[2]
        if name in ("log1", "log2", "log3", "log4"):
            # Read back by its first topic, which must be known: a constant, or the selector (DSS's ``note``).
            first = _strip(args[0])
            if first == mk("sig") and selector is not None:
                event = ("topic0", selector << 224, len(args) - 1)
            elif _constant(first) and isinstance(first[1], int):
                event = ("topic0", first[1], len(args) - 1)
            else:
                continue
            args = args[1:]
        else:
            event = (name, len(args))
        named = _parts(args)
        if event in out or not all(_names(k, named, hashed) for k in keys):
            continue
        if values and not (_names(value, named, hashed) or all(_names(v, named, hashed) for v in values)):
            continue
        # Emitted wherever the write leaves the entry set (the cheap shape first, then the connectives).
        if _implies(sets, made) or _implies_as_logic(sets, made):
            out.add(event)
    if not out:
        return None
    return out.union(*(v for v in listed.values() if v is not None))


def _iterated(t: Term) -> bool:
    """A value a loop leaves after more iterations than the lowering ran (``loop:N``)."""
    t = _strip(t)
    return isinstance(t, tuple) and bool(t) and t[0] in ("opaque", "unknown") and str(t[1]).startswith("loop:")


def _from_list(key: Term, entries: list, lists: dict) -> set | None:
    """The events naming every value a storage list ``key`` is read from (``proposers[i]``) has held, when every
    write to its elements leaves zero, another of its elements (a swap before a pop), or a value an event on that
    path names; ``None`` otherwise, or when ``key`` is no list element."""
    k = _strip(key)
    if isinstance(k, tuple) and k and k[0] == "ite":
        # One element or another (a swap's last element, or the one removed when it is the last).
        branches = [b if _constant(b) else _from_list(b, entries, lists) for b in (k[2], k[3])]
        if any(b is None for b in branches):
            return None
        return set().union(*(b for b in branches if isinstance(b, set)))
    if not (isinstance(k, tuple) and k and k[0] == "load" and k[1] == THIS and k[3] and k[3][-1][0] == "k"):
        return None
    fields = tuple(x for kind, x in k[3] if kind == "f")
    if sum(1 for kind, _ in k[3] if kind == "k") != 1:
        return None
    sig = (repr(k[2]), fields)
    if sig in lists:
        return lists[sig]
    lists[sig] = None  # while asked: a list whose writes need this very list doesn't count
    if ("index",) not in lists:
        # Each path's writes to list elements by the list they write, once: a contract's paths are many.
        index: dict = {}
        for i, (_, store, _) in enumerate(entries):
            for loc, value in store.items():
                if loc[0] == THIS and loc[2] and loc[2][-1][0] == "k":
                    at = (repr(loc[1]), tuple(x for kind, x in loc[2] if kind == "f"))
                    index.setdefault(at, {}).setdefault(i, []).append((loc, value))
        lists[("index",)] = index
    found: set = set()
    for i, own in lists[("index",)].get(sig, {}).items():
        pc, store, selector = entries[i]
        # A loop's further iterations write what the unrolled ones did: unknown as a value, checked through those.
        unrolled = any(not _iterated(v) for at, value in own for v in _set_values(value, mk("load", *at)))
        for loc, value in own:
            for v in _set_values(value, mk("load", *loc)):
                moved = _strip(v)
                if (
                    (unrolled and _iterated(moved))
                    or _constant(moved)
                    or (
                        isinstance(moved, tuple)
                        and moved[:2] == ("load", THIS)
                        and repr(moved[2]) == sig[0]
                        and tuple(x for kind, x in moved[3] if kind == "f") == fields
                    )
                ):
                    continue
                events = _logging(pc, store, selector, value, mk("load", *loc), [v], False)
                if events is None:
                    return None
                found |= events
    lists[sig] = found
    return found


def _set_values(value: Term, old: Term) -> list[Term]:
    """The values a write of ``value`` may leave that aren't zero or what was there."""
    if value == old or _zero(value):
        return []
    if isinstance(value, tuple) and value and value[0] == "ite":
        return [*_set_values(value[2], old), *_set_values(value[3], old)]
    return [value]


def _sets(value: Term, old: Term) -> Term:
    """When a write of ``value`` (a choice among values, per path) can leave the entry nonzero and changed."""
    if value == old or _zero(value):
        return FALSE
    if isinstance(value, tuple) and value and value[0] == "ite":
        return mk_or([mk_and([value[1], _sets(value[2], old)]), mk_and([mk_not(value[1]), _sets(value[3], old)])])
    return TRUE


def _zero(value: Term) -> bool:
    if not isinstance(value, tuple) or not value:
        return False
    if value[0] == "const":
        return value[1] in (0, False)
    if value[0] == "struct":
        return all(_zero(v) for v in value[2])
    return False


def _implies(a: Term, b: Term, depth: int = 0) -> bool:
    """Whether ``a`` implies ``b``, shown from their shapes alone (no solver): ``False`` when it can't be."""
    if b == TRUE or a == FALSE or a == b:
        return True
    if depth > 12:
        return False
    kind_a, kind_b = a[0], b[0]
    if kind_a == "or":
        return all(_implies(x, b, depth + 1) for x in a[1])
    if kind_b == "and":
        return all(_implies(a, y, depth + 1) for y in b[1])
    if kind_b == "or" and any(_implies(a, y, depth + 1) for y in b[1]):
        return True
    if kind_a == "and" and (b in a[1] or any(_implies(x, b, depth + 1) for x in a[1])):
        return True
    if kind_b == "ite":
        c, then, other = b[1], b[2], b[3]
        if _implies(a, then, depth + 1) and _implies(a, other, depth + 1):
            return True
        if _implies(a, c, depth + 1) and _implies(a, then, depth + 1):
            return True
        if _implies(a, mk_not(c), depth + 1) and _implies(a, other, depth + 1):
            return True
    if kind_a == "ite":
        c, then, other = a[1], a[2], a[3]
        return _implies(mk_and([c, then]), b, depth + 1) and _implies(mk_and([mk_not(c), other]), b, depth + 1)
    return False


_PROPOSITIONAL_MS = 150  # z3's time for one implication between path conditions
_PROPOSITIONAL_SECONDS = 2.0  # and for all of one contract's: past it, an implication isn't shown
_PROPOSITIONAL: dict = {}
_spent = {"left": _PROPOSITIONAL_SECONDS}  # z3 seconds the contract being asked about has left


def _implies_as_logic(a: Term, b: Term) -> bool:
    """``_implies`` by the connectives alone, each condition they combine a variable of its own: ``a`` implies ``b``
    whatever the conditions mean (two merged loop iterations' ``ite`` chains). ``False`` when z3 can't show it."""
    import time

    key = (a, b, term_epoch())
    if key not in _PROPOSITIONAL:
        if _spent["left"] <= 0:
            return False  # not shown, and not remembered
        if len(_PROPOSITIONAL) > 50_000:
            _PROPOSITIONAL.clear()
        started = time.monotonic()
        _PROPOSITIONAL[key] = _propositional(a, b)
        _spent["left"] -= time.monotonic() - started
    return _PROPOSITIONAL[key]


def _propositional(a: Term, b: Term) -> bool:
    import z3

    atoms: dict = {}

    def enc(t: Term, depth: int = 0) -> Any:
        if t == TRUE:
            return z3.BoolVal(True)
        if t == FALSE:
            return z3.BoolVal(False)
        kind = t[0]
        if kind == "and":
            return z3.And([enc(x, depth + 1) for x in t[1]])
        if kind == "or":
            return z3.Or([enc(x, depth + 1) for x in t[1]])
        if kind == "not":
            return z3.Not(enc(t[1], depth + 1))
        if kind == "ite" and _boolean(t[2]) and _boolean(t[3]):
            return z3.If(enc(t[1], depth + 1), enc(t[2], depth + 1), enc(t[3], depth + 1))
        if t not in atoms:
            atoms[t] = z3.Bool(f"a{len(atoms)}")
        return atoms[t]

    solver = z3.Solver()
    solver.set("timeout", _PROPOSITIONAL_MS)
    try:
        solver.add(enc(a), z3.Not(enc(b)))
    except RecursionError:
        return False
    return solver.check() == z3.unsat


def _boolean(t: Term) -> bool:
    return t in (TRUE, FALSE) or (isinstance(t, tuple) and t and t[0] in ("and", "or", "not", "cmp", "ite"))


def _strip(t: Any) -> Any:
    """A value under conversions, or packed whole into a word (``mstore(p, holder)`` read back as 32 bytes)."""
    while isinstance(t, tuple) and t:
        if t[0] == "conv":
            t = t[2]
        elif t[0] == "slice" and t[2] == 0 and t[3] == 32:
            t = t[1]
        else:
            break
    return t


def _parts(args: tuple) -> set:
    """What an event's arguments name: each argument, and each value an encoded one packs."""
    out: set = set()
    for a in args:
        a = _strip(a)
        out.add(a)
        if isinstance(a, tuple) and a and a[0] == "enc":
            out |= {_strip(x) for x in a[2]}
    return out


def _inputs(h: Term) -> list:
    return [x for i in h[2] for x in (i[2] if isinstance(i, tuple) and i and i[0] == "enc" else (i,))]


def _names(key: Term, named: set, hashed: bool) -> bool:
    key = _strip(key)
    if _constant(key):
        return True
    if key in named and not (hashed and key[0] == "hash"):
        return True
    if key[0] == "hash":
        return all(_names(x, named, False) for x in _inputs(key))
    return False


def _constant(t: Any) -> bool:
    t = _strip(t)
    return isinstance(t, tuple) and bool(t) and t[0] in ("const", "constant")


def _may_be_entry(slot: Any) -> bool:
    """Whether a raw slot may be where the compiler keeps a mapping's entry, ``keccak256(key . slot)`` or a field
    past it: any hash of exactly 64 bytes, or a slot of no known shape. A constant (an ERC-1967 slot) or a hash of
    other length can't be."""
    slot = _strip(slot)
    if _constant(slot):
        return False
    if isinstance(slot, tuple) and slot[:2] == ("op", "add"):
        hashes = [_strip(x) for x in slot[2] if _strip(x)[0] == "hash"]
        return not hashes or any(_may_be_entry(h) for h in hashes)
    if not (isinstance(slot, tuple) and slot and slot[0] == "hash"):
        return True
    total = 0
    for part in slot[2]:
        if isinstance(part, tuple) and part and part[0] == "enc" and part[1] == "abi.encodePacked":
            widths = [packed_width(x) for x in part[2]]
            if any(w is None for w in widths):
                return True
            total += sum(widths)
        elif isinstance(part, tuple) and part and part[0] == "enc":
            total += 32 * len(part[2])
        else:
            width = packed_width(part)
            if width is None:
                return True
            total += width
    return total == 64


def _shape(slot: Any) -> tuple | None:
    """A hashed slot's parts, each its constant value or ``None`` where it varies."""
    slot = _strip(slot)
    if not isinstance(slot, tuple) or not slot or slot[0] != "hash":
        return None
    return tuple(_strip(x)[1] if _constant(x) and _strip(x)[0] == "const" else None for x in _inputs(slot))


def _offset_of_hash(slot: Any) -> bool:
    """``keccak256(...) + i``: an array's or struct's slot past a hash, never itself a whole hash."""
    slot = _strip(slot)
    return (
        isinstance(slot, tuple)
        and slot[:2] == ("op", "add")
        and any(_strip(x)[0] == "hash" for x in slot[2])
        and not all(_strip(x)[0] == "hash" for x in slot[2])
    )


__all__ = ["keyed_by", "logged", "logged_raw", "members", "written_by"]
