"""W2 — the ordering witness: does a *clearing* write to a storage record
must-precede every external call the function can make?

The claim this module proves, and nothing wider:

    W2 holds for record ``R`` iff there is a node ``W`` writing ``R`` with a
    clearing IR shape such that for EVERY node ``C`` performing an external
    call, ``W`` must-precede ``C``.

``must-precede`` is Slither's CFG dominance (``Node.dominators``), refined with
the IR index when both sites share a node, and lifted across ONE internal-call
hop by the composition rule in :func:`_precedes`.

Why this is a new fact rather than a read of the sink list
---------------------------------------------------------
``effects._build_sink_records`` assigns sink ordinals in DISCOVERY order, not
execution order: modifier subtrees are positioned at their call site, guard
sinks land after body sinks, and the ``(kind, target, selector)`` de-dup keeps
the FIRST index — so a variable written both before and after a call collapses
onto the earlier write. Reading an ordinal as an ordering fact over-claims in
exactly the direction this witness must never fail. The external-call
enumerator here is therefore built from scratch, and it enumerates the two IR
ops the sink classifier does not handle at all — ``Transfer`` and ``Send``,
which is what ``payable(x).transfer(v)`` and ``.send(v)`` lower to. Missing
those would leave a payout invisible to the ordering check.

Fail-closed throughout: the verdict is three-valued, absence of a proof is
``not_determined`` with the reason that produced it, and the refusal vocabulary
is closed (:data:`REFUSAL_REASONS`).
"""

from __future__ import annotations

from typing import Any, TypedDict

from typing_extensions import NotRequired

from utils.scoring_status import NOT_DETERMINED

from .revert_detect import _ir_is_assert, _ir_is_require

# ---------------------------------------------------------------------------
# Owner ruling F2-CLEARING (2026-08-09): a boolean member zeroing
# (``bid.isActive = false``) counts as a clearing write ONLY when a mandatory
# predicate on that same member sits on the function's revert path — which is
# what makes the "a re-entry reverts" argument sound rather than name-shaped.
# The strict shapes (delete / zero-assign / decrement) are unconditional; this
# one toggle is the whole of the ruling, so reversing it is a one-line change.
# ---------------------------------------------------------------------------
FLAG_FLIP_CLEARING_ENABLED = True


PROVEN = "proven_ordering"

#: The one basis this module can publish. The verified-guard alternative
#: satisfier (``w2_verified_guard``) is a different proof and lives in U4.
W2_BASIS_CLEAR_DOMINATES_CALLS = "clear_dominates_calls"

#: Per-iteration ordering is all a same-record claim needs, and all dominance
#: inside a loop body proves. It says nothing cross-iteration and must not
#: pretend to, so the proof travels with this disclosure.
DISCLOSURE_CROSS_ITERATION = "cross_iteration_ordering_not_proven"

# --- the closed refusal vocabulary -----------------------------------------
#: candidate clearing writes exist, none must-precedes every external call
CLEARING_WRITE_DOES_NOT_DOMINATE_CALLS = "clearing_write_does_not_dominate_calls"
#: no write to the record has an admissible clearing shape anywhere in reach
NO_CLEARING_WRITE = "no_clearing_write"
#: an inline-assembly state access makes the write set unknowable
ASSEMBLY_STATE_ACCESS = "assembly_state_access"
#: the only candidates sit deeper than one hop, or in a sibling callee
CROSS_UNIT_ORDERING_UNPROVEN = "cross_unit_ordering_unproven"
#: write and call are in different loop nestings — per-iteration ordering does
#: not compose across them
LOOP_NESTING_MISMATCH = "loop_nesting_mismatch"
#: the call walk hit its depth cap or a recursive cycle, so "every external
#: call" is not a set this pass closed
CALL_ENUMERATION_INCOMPLETE = "call_enumeration_incomplete"
#: the caller named no record, or named one with no canonical base
RECORD_NOT_RESOLVABLE = "record_not_resolvable"

REFUSAL_REASONS: frozenset[str] = frozenset(
    {
        CLEARING_WRITE_DOES_NOT_DOMINATE_CALLS,
        NO_CLEARING_WRITE,
        ASSEMBLY_STATE_ACCESS,
        CROSS_UNIT_ORDERING_UNPROVEN,
        LOOP_NESTING_MISMATCH,
        CALL_ENUMERATION_INCOMPLETE,
        RECORD_NOT_RESOLVABLE,
    }
)

# --- clearing shapes, published so a consumer can see WHICH proof it got ----
SHAPE_DELETE = "delete"
SHAPE_ZERO_ASSIGNMENT = "zero_assignment"
SHAPE_DECREMENT = "decrement"
SHAPE_ASSIGNED_DIFFERENCE = "assigned_difference"
SHAPE_FLAG_FLIP = "flag_flip_with_mandatory_predicate"


class RecordRef(TypedDict):
    """The record W1 bound the amount to, in the ENTRY function's terms.

    ``key_kinds`` / ``key_param_indexes`` are positional per index level and
    carry the same vocabulary the amount producer publishes
    (``param`` / ``msg_sender`` / ``indeterminate``). A level this pass cannot
    match exactly is a level it refuses on — a write to a *different* cell of
    the same mapping is not a clearing write for this record."""

    base_canonical: str
    member_path: NotRequired[list[str]]
    key_kinds: NotRequired[list[str]]
    key_param_indexes: NotRequired[list[int | None]]


class OrderingWitness(TypedDict):
    """Three-valued. ``state`` is the only always-present key; a refusal always
    carries ``reason``, a proof always carries ``w2_basis``."""

    state: str
    w2_basis: NotRequired[str]
    record: NotRequired[str]
    clearing_shape: NotRequired[str]
    disclosures: NotRequired[list[str]]
    reason: NotRequired[str]


# A resolved access path step: ("index", key_kind, key_param_index) or
# ("member", member_name, None). Ordered from the base variable outwards.
_Step = tuple[str, str, "int | None"]

# Ops that hand control to code this compilation unit does not own. "Every
# external call", not "every dangerous external call" (S1 §2.3 / fork F1): the
# analysis cannot prove a callee is view, so narrowing would be policy, not a
# fact. ``LibraryCall`` is here because ``using SafeTransferLib for IERC20``
# puts the real token call inside it; ``Transfer``/``Send`` are here because
# nothing else in the pipeline sees them.
_EXTERNAL_CALL_OPS = frozenset({"HighLevelCall", "LibraryCall", "LowLevelCall", "NewContract", "Transfer", "Send"})

# Inline-assembly SolidityCalls that transfer control. ``sstore``/``sload``/
# ``keccak256`` and the require/revert family are deliberately absent.
_CONTROL_TRANSFER_SOLIDITY_PREFIXES = (
    "selfdestruct(",
    "suicide(",
    "call(",
    "callcode(",
    "delegatecall(",
    "staticcall(",
    "create(",
    "create2(",
)

# How deep the CALL enumeration walks before it declares the set unclosed. The
# clearing write is capped separately at one hop (S1 §2.3); this cap only
# governs whether we can claim to have seen every call.
_MAX_CALL_WALK_DEPTH = 6

# The clearing write may be in the entry unit (path length 1) or in a callee
# invoked directly from it (path length 2). Deeper refuses.
_MAX_WRITE_PATH = 2

# Ceiling on units walked per query, since the same helper is re-walked once per
# call site by design.
_MAX_WALKED_UNITS = 256

# ---------------------------------------------------------------------------
# Slither shims — duck-typed, matching effects.py's convention of never
# importing slither at module scope.
# ---------------------------------------------------------------------------


def _irs(node: Any) -> list[Any]:
    return list(getattr(node, "irs", []) or [])


def _nodes(unit: Any) -> list[Any]:
    return list(getattr(unit, "nodes", []) or [])


def _op(ir: Any) -> str:
    return type(ir).__name__


def _var_kind(value: Any) -> str:
    return type(value).__name__


def _node_id(node: Any) -> int:
    return int(getattr(node, "node_id", -1))


def _node_type_name(node: Any) -> str:
    node_type = getattr(node, "type", None)
    return str(getattr(node_type, "name", node_type) or "")


def _dominators(node: Any) -> list[Any]:
    return list(getattr(node, "dominators", []) or [])


def _is_dominated_by(node: Any, candidate: Any) -> bool:
    return any(dominator is candidate for dominator in _dominators(node))


def _solidity_call_name(ir: Any) -> str:
    function = getattr(ir, "function", None)
    return str(getattr(function, "name", None) or function or "")


def _unit_key(unit: Any) -> str:
    return str(getattr(unit, "canonical_name", None) or getattr(unit, "full_name", None) or id(unit))


def _is_zero_constant(value: Any) -> bool:
    """A literal zero — the numeric one only. ``False`` is a different ruling
    (the flag-flip subclass) and must not enter through this door."""
    # Deferred: effects.py imports this module, so the reuse cannot be a
    # module-scope import.
    from .effects import _is_zero_literal

    if _var_kind(value) != "Constant":
        return False
    raw = getattr(value, "value", None)
    if isinstance(raw, bool):
        return False
    return _is_zero_literal(str(raw if raw is not None else value))


def _is_false_constant(value: Any) -> bool:
    return _var_kind(value) == "Constant" and getattr(value, "value", None) is False


def _is_true_constant(value: Any) -> bool:
    return _var_kind(value) == "Constant" and getattr(value, "value", None) is True


def _is_subtraction_ir(ir: Any) -> bool:
    from .effects import _is_subtraction

    return _op(ir) == "Binary" and _is_subtraction(str(getattr(ir, "type", None)))


# ---------------------------------------------------------------------------
# Access-path resolution.
# ---------------------------------------------------------------------------


def _ref_defs(unit: Any) -> dict[int, Any]:
    """``id(ReferenceVariable) -> the Index/Member IR that built it``.

    Only those two ops are recorded: a ``Delete`` re-uses the *parent* ref as
    its ``lvalue``, so a def map built from every lvalue would overwrite the
    Index that the deleted ref's own chain has to walk through. First write
    wins for the same reason."""
    defs: dict[int, Any] = {}
    for node in _nodes(unit):
        for ir in _irs(node):
            if _op(ir) not in ("Index", "Member"):
                continue
            lvalue = getattr(ir, "lvalue", None)
            if lvalue is None:
                continue
            defs.setdefault(id(lvalue), ir)
    return defs


def _value_defs(unit: Any) -> dict[int, Any]:
    """``id(TemporaryVariable) -> the IR that computed it``, for reading one
    level through a condition's own arithmetic and through the ``x = b - amount``
    form of a decrement."""
    defs: dict[int, Any] = {}
    for node in _nodes(unit):
        for ir in _irs(node):
            if _op(ir) not in ("Binary", "Unary", "Assignment", "TypeConversion"):
                continue
            lvalue = getattr(ir, "lvalue", None)
            if lvalue is None or _var_kind(lvalue) != "TemporaryVariable":
                continue
            defs.setdefault(id(lvalue), ir)
    return defs


def _local_defs(unit: Any) -> dict[int, list[Any]]:
    """``id(LocalVariable) -> every IR that assigns it``. Locals, unlike the
    SSA-ish temporaries, are re-assignable, so the list is kept whole: a local
    written twice names no single value and is read as unknown rather than as
    its first definition."""
    defs: dict[int, list[Any]] = {}
    for node in _nodes(unit):
        for ir in _irs(node):
            lvalue = getattr(ir, "lvalue", None)
            if lvalue is None or _var_kind(lvalue) != "LocalVariable":
                continue
            defs.setdefault(id(lvalue), []).append(ir)
    return defs


class _Scope:
    """Everything the classifier needs about one walked unit."""

    __slots__ = ("unit", "refs", "values", "locals", "bindings")

    def __init__(self, unit: Any, bindings: dict[int, _Step]) -> None:
        self.unit = unit
        self.refs = _ref_defs(unit)
        self.values = _value_defs(unit)
        self.locals = _local_defs(unit)
        self.bindings = bindings

    def path_of(self, value: Any) -> tuple[str, tuple[_Step, ...]] | None:
        return _resolve_access_path(value, self.refs, self.bindings)


def _key_step(value: Any, bindings: dict[int, _Step]) -> _Step:
    """Classify one index level in ENTRY terms. ``bindings`` maps a unit's own
    parameter objects onto what the call site passed, which is what lets
    ``_balances[account]`` inside ``_burn`` read as the caller's own cell."""
    if value is None:
        return ("index", "indeterminate", None)
    bound = bindings.get(id(value))
    if bound is not None:
        return bound
    name = str(getattr(value, "name", "") or "")
    if name == "msg.sender":
        return ("index", "msg_sender", None)
    return ("index", "indeterminate", None)


def _resolve_access_path(
    value: Any, defs: dict[int, Any], bindings: dict[int, _Step]
) -> tuple[str, tuple[_Step, ...]] | None:
    """``(base canonical name, steps)`` for a state-variable access, or ``None``
    when the chain leaves storage or cannot be followed."""
    steps: list[_Step] = []
    current = value
    for _ in range(16):
        kind = _var_kind(current)
        if kind == "StateVariable":
            canonical = getattr(current, "canonical_name", None)
            if not canonical:
                return None
            return str(canonical), tuple(reversed(steps))
        if kind != "ReferenceVariable":
            return None
        ir = defs.get(id(current))
        if ir is None:
            return None
        op = _op(ir)
        if op == "Index":
            steps.append(_key_step(getattr(ir, "variable_right", None), bindings))
            current = getattr(ir, "variable_left", None)
        elif op == "Member":
            member = getattr(ir, "variable_right", None)
            steps.append(("member", str(getattr(member, "value", None) or member or ""), None))
            current = getattr(ir, "variable_left", None)
        else:
            return None
    return None


def _record_steps(record: RecordRef) -> tuple[_Step, ...] | None:
    """The record's own access path. Index levels first, then the member path —
    the shape ``mapping[key].member`` produces. A record whose real layout
    interleaves them differently simply never matches, which is the fail-closed
    direction."""
    kinds = record.get("key_kinds")
    indexes = record.get("key_param_indexes")
    members = record.get("member_path")
    # An ABSENT list is the producer's "not determined" — its sites disagreed or
    # it never resolved one. Reading it as an empty path would widen the record
    # to the whole element and let a write to a sibling member clear it.
    if not isinstance(kinds, list) or not isinstance(indexes, list) or not isinstance(members, list):
        return None
    if len(indexes) != len(kinds):
        return None
    steps: list[_Step] = []
    for level, kind in enumerate(kinds):
        if kind not in ("param", "msg_sender"):
            # An indeterminate key names no cell, so no write can be shown to
            # clear THIS record rather than a sibling one.
            return None
        if kind == "param" and indexes[level] is None:
            return None
        steps.append(("index", str(kind), indexes[level] if kind == "param" else None))
    for member in members:
        steps.append(("member", str(member), None))
    return tuple(steps)


# ---------------------------------------------------------------------------
# Clearing-write classification.
# ---------------------------------------------------------------------------


def _element_steps(steps: tuple[_Step, ...]) -> tuple[_Step, ...]:
    """The record's steps with its trailing member path stripped — i.e. the
    storage ELEMENT the record lives in. Two members of one struct element are
    the same element; two elements of one mapping are not."""
    end = len(steps)
    while end > 0 and steps[end - 1][0] == "member":
        end -= 1
    return steps[:end]


def _reads_record_value(scope: _Scope, value: Any, target: tuple[str, tuple[_Step, ...]]) -> bool:
    """Is ``value`` the record's own stored value? Either the record ref itself,
    or a local assigned from it exactly once. A local written twice names no
    single value."""
    if value is None:
        return False
    if scope.path_of(value) == target:
        return True
    source: Any = None
    if _var_kind(value) == "TemporaryVariable":
        source = scope.values.get(id(value))
    elif _var_kind(value) == "LocalVariable":
        definitions = scope.locals.get(id(value)) or []
        source = definitions[0] if len(definitions) == 1 else None
    if source is None or _op(source) != "Assignment":
        return False
    return scope.path_of(getattr(source, "rvalue", None)) == target


def _subtracts_from_the_record(scope: _Scope, binary: Any, target: tuple[str, tuple[_Step, ...]]) -> bool:
    """A debit takes the record's own prior value as its minuend.
    ``amount = cap - used`` is arithmetic that happens to subtract, and may
    RAISE the record — it is not a clearing write."""
    return _reads_record_value(scope, getattr(binary, "variable_left", None), target)


def _condition_pins_record(scope: _Scope, value: Any, target: tuple[str, tuple[_Step, ...]], depth: int = 0) -> bool:
    """Does this condition, taken as a whole, require the member to be TRUE?

    The ruling's soundness argument is that a re-entry REVERTS, which needs the
    flip to falsify the predicate — not merely to be mentioned by it. So the
    admissible forms are the positive read (``require(m)``), the explicit
    ``require(m == true)``, and a top-level ``&&`` conjunct of either. An
    ``||``, a negation, a comparison against a parameter or another cell, or a
    predicate on a different element all leave a way for the second entry to
    pass, and refuse."""
    if depth > 4 or value is None:
        return False
    if scope.path_of(value) == target:
        return True
    source = scope.values.get(id(value))
    if source is None:
        return False
    op = _op(source)
    if op == "Assignment":
        return _condition_pins_record(scope, getattr(source, "rvalue", None), target, depth + 1)
    if op != "Binary":
        return False
    binary_type = str(getattr(source, "type", None) or "")
    left = getattr(source, "variable_left", None)
    right = getattr(source, "variable_right", None)
    if binary_type.endswith(".ANDAND"):
        # Every conjunct must hold, so one that pins the member pins the whole.
        return _condition_pins_record(scope, left, target, depth + 1) or _condition_pins_record(
            scope, right, target, depth + 1
        )
    if binary_type.endswith(".EQUAL"):
        return any(
            scope.path_of(operand) == target and _is_true_constant(other)
            for operand, other in ((left, right), (right, left))
        )
    return False


def _has_mandatory_member_predicate(
    scope: _Scope,
    write_node: Any,
    write_ir_index: int,
    target: tuple[str, tuple[_Step, ...]],
) -> bool:
    """The F2-CLEARING conjunct: a require/assert pinning the SAME member true,
    on the mandatory path to the flip. Mandatory means the predicate's node
    dominates the flip (or precedes it inside the same node) — a check reachable
    only under an ``if`` proves nothing about the entries that skip it."""
    for node in _nodes(scope.unit):
        if not (node is write_node or _is_dominated_by(write_node, node)):
            continue
        for index, ir in enumerate(_irs(node)):
            if not (_ir_is_require(ir) or _ir_is_assert(ir)):
                continue
            if node is write_node and index >= write_ir_index:
                continue
            arguments = list(getattr(ir, "arguments", []) or [])
            if arguments and _condition_pins_record(scope, arguments[0], target):
                return True
    return False


def _clearing_shape(
    scope: _Scope,
    ir: Any,
    node: Any,
    ir_index: int,
    base: str,
    steps: tuple[_Step, ...],
) -> str | None:
    """The admissible shape this IR clears the record with, or ``None``.

    Admissible: ``Delete`` on the record ref or any prefix of it; an
    ``Assignment`` of a zero literal to it; a subtraction OF ITS OWN VALUE,
    either compound (``r.shares -= x``) or via the OZ ``_burn`` form
    (``_balances[a] = b - amount``); and — behind
    :data:`FLAG_FLIP_CLEARING_ENABLED` — a boolean member of the same element
    zeroed under a mandatory predicate pinning that member. Everything else is
    not a clearing write: a caller-supplied value, a struct-wide assignment, an
    increment, an assembly ``sstore``."""
    op = _op(ir)
    target = (base, steps)

    if op == "Delete":
        resolved = scope.path_of(getattr(ir, "variable", None))
        if resolved is None:
            return None
        deleted_base, deleted_steps = resolved
        # Deleting a container clears everything under it, so a PREFIX counts.
        if deleted_base == base and steps[: len(deleted_steps)] == deleted_steps:
            return SHAPE_DELETE
        return None

    lvalue = getattr(ir, "lvalue", None)
    if lvalue is None:
        return None
    resolved = scope.path_of(lvalue)
    if resolved is None or resolved[0] != base:
        return None
    written = resolved[1]

    if written == steps:
        if _is_subtraction_ir(ir):
            return SHAPE_DECREMENT if _subtracts_from_the_record(scope, ir, target) else None
        if op == "Assignment":
            rvalue = getattr(ir, "rvalue", None)
            if _is_zero_constant(rvalue):
                return SHAPE_ZERO_ASSIGNMENT
            source = scope.values.get(id(rvalue)) if rvalue is not None else None
            if source is not None and _is_subtraction_ir(source) and _subtracts_from_the_record(scope, source, target):
                return SHAPE_ASSIGNED_DIFFERENCE
        return None

    # The F2-CLEARING subclass: a boolean member of the SAME element zeroed. The
    # quantity member is untouched, so this is a guard-shaped argument, not a
    # debit — it only holds because a mandatory predicate on that same member
    # makes the second entry revert.
    if not (FLAG_FLIP_CLEARING_ENABLED and op == "Assignment"):
        return None
    if not _is_false_constant(getattr(ir, "rvalue", None)):
        return None
    if not written or written[-1][0] != "member" or written[:-1] != _element_steps(steps):
        return None
    if _has_mandatory_member_predicate(scope, write_node=node, write_ir_index=ir_index, target=(base, written)):
        return SHAPE_FLAG_FLIP
    return None


# ---------------------------------------------------------------------------
# The walk: external calls and clearing writes, each with its call path.
# ---------------------------------------------------------------------------


class _Site:
    """A discovered site, positioned by the chain of call sites that reaches it.

    ``path[j]`` is the ``(node, ir index)`` of the call made in ``units[j]``;
    the LAST element is the site's own ``(node, ir index)``. Keying a site on
    its whole path — rather than on the callee's name, the way the sink walk
    does — is what keeps a helper invoked twice at two positions instead of
    one."""

    __slots__ = ("path", "units", "shape")

    def __init__(self, path: tuple[tuple[Any, int], ...], units: tuple[Any, ...], shape: str | None = None) -> None:
        self.path = path
        self.units = units
        self.shape = shape


class _WalkState:
    __slots__ = ("calls", "writes", "deep_writes", "incomplete", "budget")

    def __init__(self) -> None:
        self.calls: list[_Site] = []
        self.writes: list[_Site] = []
        self.deep_writes: int = 0
        self.incomplete: bool = False
        # Walking per (unit, call-site) rather than per unit is what keeps a
        # helper invoked twice from collapsing to one position — and is also
        # what makes the walk exponential in a wide call graph. Exhausting the
        # budget is an unclosed call set, i.e. a refusal, never a shortened one.
        self.budget: int = _MAX_WALKED_UNITS


def _is_external_call_ir(ir: Any) -> bool:
    if _op(ir) in _EXTERNAL_CALL_OPS:
        return True
    if _op(ir) != "SolidityCall":
        return False
    return _solidity_call_name(ir).startswith(_CONTROL_TRANSFER_SOLIDITY_PREFIXES)


def _callee_bindings(callee: Any, ir: Any, caller_bindings: dict[int, _Step]) -> dict[int, _Step]:
    """Map the callee's own parameters onto what the call site passed, in ENTRY
    terms. Anything not resolvable binds to ``indeterminate``, which makes a
    key level unmatchable rather than wrongly matched."""
    bindings: dict[int, _Step] = {}
    arguments = list(getattr(ir, "arguments", []) or [])
    for position, parameter in enumerate(list(getattr(callee, "parameters", []) or [])):
        if position >= len(arguments):
            break
        bindings[id(parameter)] = _key_step(arguments[position], caller_bindings)
    return bindings


def _walk(
    unit: Any,
    prefix: tuple[tuple[Any, int], ...],
    unit_chain: tuple[Any, ...],
    bindings: dict[int, _Step],
    on_path: frozenset[str],
    depth: int,
    base: str,
    steps: tuple[_Step, ...],
    state: _WalkState,
) -> None:
    scope = _Scope(unit, bindings)
    for node in _nodes(unit):
        irs = _irs(node)
        for index, ir in enumerate(irs):
            position = prefix + ((node, index),)
            if _is_external_call_ir(ir):
                state.calls.append(_Site(position, unit_chain))
            if _op(ir) == "InternalDynamicCall":
                # An internal function POINTER: the body it reaches is chosen at
                # runtime, so neither the calls under it nor its writes are ours
                # to enumerate. A dynamic call that itself pays out is exactly
                # the hole a vacuous "no call precedes the clear" would hide.
                state.incomplete = True
            shape = _clearing_shape(scope, ir, node, index, base, steps)
            if shape is not None:
                if len(position) <= _MAX_WRITE_PATH:
                    state.writes.append(_Site(position, unit_chain, shape))
                else:
                    state.deep_writes += 1
            if _op(ir) not in ("InternalCall", "LibraryCall"):
                continue
            callee = getattr(ir, "function", None)
            if callee is None or not _nodes(callee):
                # An unimplemented callee (a `virtual` hook, an unresolved
                # internal target) has a body we did not read, so the calls
                # under it are not calls we ruled out.
                state.incomplete = True
                continue
            key = _unit_key(callee)
            if key in on_path:
                # Recursion: the call set below this point is not one we closed.
                state.incomplete = True
                continue
            if depth + 1 > _MAX_CALL_WALK_DEPTH or state.budget <= 0:
                state.incomplete = True
                continue
            state.budget -= 1
            _walk(
                callee,
                position,
                unit_chain + (callee,),
                _callee_bindings(callee, ir, bindings),
                on_path | {key},
                depth + 1,
                base,
                steps,
                state,
            )


# ---------------------------------------------------------------------------
# The ordering query.
# ---------------------------------------------------------------------------


def _loop_index(unit: Any, cache: dict[int, dict[int, frozenset[int]]]) -> dict[int, frozenset[int]]:
    """``node_id -> the loop headers that actually CONTAIN it``.

    Containment is the natural-loop definition: header ``H`` (an ``IFLOOP``)
    contains ``N`` when ``H`` dominates ``N`` *and* ``N`` can reach ``H`` again
    along the back edge. Reading enclosure off the dominator set alone would put
    every node AFTER the loop inside it — they are dominated by the header too —
    and would attach a cross-iteration residual to a straight-line pair."""
    key = id(unit)
    cached = cache.get(key)
    if cached is not None:
        return cached
    headers = [node for node in _nodes(unit) if _node_type_name(node) == "IFLOOP"]
    # Nodes that can reach each header again — a backward walk from it, which is
    # the back edge read in the only direction the CFG exposes.
    reaches: dict[Any, set[int]] = {}
    for header in headers:
        seen: set[int] = set()
        stack = [header]
        while stack:
            current = stack.pop()
            current_id = _node_id(current)
            if current_id in seen:
                continue
            seen.add(current_id)
            stack.extend(list(getattr(current, "fathers", []) or []))
        reaches[id(header)] = seen
    index: dict[int, frozenset[int]] = {}
    for node in _nodes(unit):
        node_id = _node_id(node)
        index[node_id] = frozenset(
            _node_id(header) for header in headers if _is_dominated_by(node, header) and node_id in reaches[id(header)]
        )
    cache[key] = index
    return index


def _loop_context(node: Any, unit: Any, cache: dict[int, dict[int, frozenset[int]]]) -> frozenset[int]:
    return _loop_index(unit, cache).get(_node_id(node), frozenset())


def _dominates_all_exits(node: Any, unit: Any) -> bool:
    """Unconditional within ``unit``, where "exit" means the point control leaves
    it for whatever runs next.

    For a MODIFIER that point is the ``PLACEHOLDER``, not the son-less tail: the
    modified function's body — and every external call in it — runs AT the
    placeholder, so a write sitting after it runs after the payout. Treating the
    son-less tail as the exit proves the DAO shape one indirection deep."""
    placeholders = [candidate for candidate in _nodes(unit) if _node_type_name(candidate) == "PLACEHOLDER"]
    exits = placeholders or [candidate for candidate in _nodes(unit) if not list(getattr(candidate, "sons", []) or [])]
    if not exits:
        return False
    return all(exit_node is node or _is_dominated_by(exit_node, node) for exit_node in exits)


def _precedes(write: _Site, call: _Site, loops: dict[int, dict[int, frozenset[int]]]) -> tuple[bool, str | None, bool]:
    """``(proved, refusal reason, in a shared loop)`` for one write/call pair."""
    shared = 0
    while (
        shared < len(write.path)
        and shared < len(call.path)
        and write.path[shared][0] is call.path[shared][0]
        and write.path[shared][1] == call.path[shared][1]
    ):
        shared += 1
    if shared >= len(write.path) or shared >= len(call.path):
        # One site is on the other's call path — the write is inside the call, or
        # is the call. Neither proves the write ran first.
        return False, CLEARING_WRITE_DOES_NOT_DOMINATE_CALLS, False
    if shared == 0 and len(write.path) > 1 and len(call.path) > 1:
        # Sibling-callee split: S1 §2.3 admits same-unit and one-hop composition
        # and refuses the rest, rather than composing two callees' interiors
        # through the entry's dominance.
        return False, CROSS_UNIT_ORDERING_UNPROVEN, False

    write_node, write_index = write.path[shared]
    call_node, call_index = call.path[shared]
    shared_unit = write.units[shared]
    write_loop = _loop_context(write_node, shared_unit, loops)
    if write_loop != _loop_context(call_node, shared_unit, loops):
        return False, LOOP_NESTING_MISMATCH, False
    if write_node is call_node:
        ordered = write_index < call_index
    else:
        ordered = _is_dominated_by(call_node, write_node)
    if not ordered:
        return False, CLEARING_WRITE_DOES_NOT_DOMINATE_CALLS, False

    # Below the divergence the write sits inside a callee: it counts only if
    # entering that callee always runs it, and only if no loop inside the callee
    # separates the two.
    for level in range(shared + 1, len(write.path)):
        nested_node = write.path[level][0]
        if not _dominates_all_exits(nested_node, write.units[level]):
            return False, CROSS_UNIT_ORDERING_UNPROVEN, False
        if _loop_context(nested_node, write.units[level], loops):
            return False, LOOP_NESTING_MISMATCH, False
    return True, None, bool(write_loop)


def _refused(reason: str) -> OrderingWitness:
    return {"state": NOT_DETERMINED, "reason": reason}


def prove_record_ordering(
    function: Any,
    record: RecordRef,
    *,
    assembly_state_access: bool,
) -> OrderingWitness:
    """W2 for one ``(function, record)`` pair. Never a bare bool: the verdict is
    proven-present or ``not_determined`` carrying the reason it refused."""
    if assembly_state_access:
        # A write we cannot see may be the one that matters.
        return _refused(ASSEMBLY_STATE_ACCESS)

    base = str(record.get("base_canonical") or "")
    steps = _record_steps(record) if base else None
    if not base or steps is None:
        return _refused(RECORD_NOT_RESOLVABLE)

    bindings: dict[int, _Step] = {
        id(parameter): ("index", "param", position)
        for position, parameter in enumerate(list(getattr(function, "parameters", []) or []))
    }
    state = _WalkState()
    _walk(function, (), (function,), bindings, frozenset({_unit_key(function)}), 0, base, steps, state)

    if state.incomplete:
        return _refused(CALL_ENUMERATION_INCOMPLETE)
    # A function with no external call at all satisfies the rule vacuously, and
    # soundly: there is no control transfer for the write to be racing. It
    # clears nothing on its own — the consumer asks this question only about a
    # flow, and a flow exists because value left through one of these ops.
    if not state.writes:
        return _refused(CROSS_UNIT_ORDERING_UNPROVEN if state.deep_writes else NO_CLEARING_WRITE)

    loops: dict[int, dict[int, frozenset[int]]] = {}
    reasons: set[str] = set()
    for write in state.writes:
        disclosed = False
        proved = True
        for call in state.calls:
            ok, reason, in_loop = _precedes(write, call, loops)
            if not ok:
                proved = False
                if reason is not None:
                    reasons.add(reason)
                break
            disclosed = disclosed or in_loop
        if not proved:
            continue
        witness: OrderingWitness = {
            "state": PROVEN,
            "w2_basis": W2_BASIS_CLEAR_DOMINATES_CALLS,
            "record": base,
            "clearing_shape": write.shape or "",
        }
        if disclosed:
            witness["disclosures"] = [DISCLOSURE_CROSS_ITERATION]
        return witness

    for candidate in (CLEARING_WRITE_DOES_NOT_DOMINATE_CALLS, LOOP_NESTING_MISMATCH, CROSS_UNIT_ORDERING_UNPROVEN):
        if candidate in reasons:
            return _refused(candidate)
    return _refused(CLEARING_WRITE_DOES_NOT_DOMINATE_CALLS)


def _record_from_flow(flow: dict[str, Any]) -> RecordRef | None:
    """The record the amount producer bound this flow's amount to, or ``None``
    where it named none — in which case the ordering question is not asked and
    no key is published."""
    base = flow.get("amount_record_variable")
    if not isinstance(base, str) or not base:
        return None
    record: RecordRef = {"base_canonical": base}
    member_path = flow.get("amount_record_member_path")
    if isinstance(member_path, list):
        record["member_path"] = [str(member) for member in member_path]
    key_kinds = flow.get("amount_record_key_kinds")
    if isinstance(key_kinds, list):
        record["key_kinds"] = [str(kind) for kind in key_kinds]
    key_indexes = flow.get("amount_record_key_param_indexes")
    if isinstance(key_indexes, list):
        record["key_param_indexes"] = [index if isinstance(index, int) else None for index in key_indexes]
    return record


def attach_record_ordering(flows: list[Any], function: Any, *, assembly_state_access: bool) -> None:
    """Publish the W2 verdict on every flow whose amount names a storage record.

    Guarded attachment: where no record is named the key is ABSENT, never a
    ``None`` or a refusal — the ordering question only exists once something
    has said which record the money came out of. Scoped to OUTBOUND moves for
    the same reason: on an inbound or merely-routed flow the entry is not the
    payer, so "was the payer's record debited first" is a different question
    and must not be answered here by accident."""
    for flow in flows:
        if flow.get("direction") != "out":
            continue
        record = _record_from_flow(flow)
        if record is None:
            continue
        flow["record_ordering"] = prove_record_ordering(function, record, assembly_state_access=assembly_state_access)
