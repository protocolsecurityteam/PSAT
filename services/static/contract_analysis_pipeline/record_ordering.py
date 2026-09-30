"""W2: does a clearing write to a storage record must-precede every external call the function can make?

Must-precede is CFG dominance, refined by IR index within a node and lifted across one internal-call hop
(:func:`_precedes`). Sink ordinals are discovery order, not execution order, so the call enumeration is built here,
including ``Transfer``/``Send`` which the sink classifier ignores. Fail-closed: proven, or ``not_determined`` with a
reason from :data:`REFUSAL_REASONS`.
"""

from __future__ import annotations

from typing import Any, TypedDict

from typing_extensions import NotRequired

from utils.scoring_status import NOT_DETERMINED

from .revert_detect import _ir_is_assert, _ir_is_require

# A boolean member zeroed (``bid.isActive = false``) is clearing only with a mandatory predicate on that member on the
# revert path, so re-entry reverts. Delete, zero-assign and decrement are unconditional.
FLAG_FLIP_CLEARING_ENABLED = True


PROVEN = "proven_ordering"

# The verified-guard alternative is a separate proof.
W2_BASIS_CLEAR_DOMINATES_CALLS = "clear_dominates_calls"

# Dominance inside a loop body proves per-iteration ordering only.
DISCLOSURE_CROSS_ITERATION = "cross_iteration_ordering_not_proven"

# Candidate writes exist but none precedes every external call.
CLEARING_WRITE_DOES_NOT_DOMINATE_CALLS = "clearing_write_does_not_dominate_calls"
NO_CLEARING_WRITE = "no_clearing_write"
# Assembly state access makes the write set unknowable.
ASSEMBLY_STATE_ACCESS = "assembly_state_access"
# The only candidates are deeper than one hop or in a sibling callee.
CROSS_UNIT_ORDERING_UNPROVEN = "cross_unit_ordering_unproven"
# Write and call in different loop nestings.
LOOP_NESTING_MISMATCH = "loop_nesting_mismatch"
# The call walk hit its cap or a cycle, so the call set isn't closed.
CALL_ENUMERATION_INCOMPLETE = "call_enumeration_incomplete"
# No record, or one without a canonical base.
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

# Published so consumers see which proof they got.
SHAPE_DELETE = "delete"
SHAPE_ZERO_ASSIGNMENT = "zero_assignment"
SHAPE_DECREMENT = "decrement"
SHAPE_ASSIGNED_DIFFERENCE = "assigned_difference"
SHAPE_FLAG_FLIP = "flag_flip_with_mandatory_predicate"


class RecordRef(TypedDict):
    """The record W1 bound the amount to, in entry-function terms.

    Key levels use the amount producer's vocabulary; a level that can't match exactly refuses (another cell of the same
    mapping isn't this record).
    """

    base_canonical: str
    member_path: NotRequired[list[str]]
    key_kinds: NotRequired[list[str]]
    key_param_indexes: NotRequired[list[int | None]]


class OrderingWitness(TypedDict):
    """``state`` always; a refusal has ``reason``, a proof ``w2_basis``."""

    state: str
    w2_basis: NotRequired[str]
    record: NotRequired[str]
    clearing_shape: NotRequired[str]
    disclosures: NotRequired[list[str]]
    reason: NotRequired[str]


# ``("index", key_kind, key_param_index)`` or ``("member", name, None)``, base outward.
_Step = tuple[str, str, "int | None"]

# Ops handing control to code outside this unit; every external call, since calls can't be proven view. ``LibraryCall``
# covers ``using SafeTransferLib``; ``Transfer``/``Send`` nothing else sees.
_EXTERNAL_CALL_OPS = frozenset({"HighLevelCall", "LibraryCall", "LowLevelCall", "NewContract", "Transfer", "Send"})

# Inline-assembly calls that transfer control; ``sstore``/``sload``/hashes and require/revert are excluded.
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

# Beyond this depth the call set is unclosed; the clearing write has its own one-hop cap.
_MAX_CALL_WALK_DEPTH = 6

# In the entry unit or a direct callee.
_MAX_WRITE_PATH = 2

# Helpers are re-walked per call site by design.
_MAX_WALKED_UNITS = 256

# Duck-typed Slither access; slither isn't imported at module scope.


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
    """A numeric zero only; ``False`` belongs to the flag-flip rule."""
    # Deferred: ``effects`` imports this module.
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


def _ref_defs(unit: Any) -> dict[int, Any]:
    """``id(ReferenceVariable) -> Index/Member IR``.

    Only those ops, first write wins: a ``Delete`` reuses the parent ref as lvalue and would overwrite the chain.
    """
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
    """``id(TemporaryVariable) -> IR``, to read one level of arithmetic and ``x = b - amount``."""
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
    """``id(LocalVariable) -> every assigning IR``; a local written twice is unknown."""
    defs: dict[int, list[Any]] = {}
    for node in _nodes(unit):
        for ir in _irs(node):
            lvalue = getattr(ir, "lvalue", None)
            if lvalue is None or _var_kind(lvalue) != "LocalVariable":
                continue
            defs.setdefault(id(lvalue), []).append(ir)
    return defs


class _Scope:
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
    """One index level in entry terms; ``bindings`` maps a callee's parameters to the call site's values
    (``_balances[account]`` in ``_burn`` reads as the caller's cell).
    """
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
    """``(base canonical name, steps)`` for a state access, or ``None``."""
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
    """The record's path: index levels, then members. Interleaved layouts never match (fail-closed)."""
    kinds = record.get("key_kinds")
    indexes = record.get("key_param_indexes")
    members = record.get("member_path")
    # An absent list is not determined; treating it as empty would let a sibling member's write clear the record.
    if not isinstance(kinds, list) or not isinstance(indexes, list) or not isinstance(members, list):
        return None
    if len(indexes) != len(kinds):
        return None
    steps: list[_Step] = []
    for level, kind in enumerate(kinds):
        if kind not in ("param", "msg_sender"):
            # An indeterminate key names no cell.
            return None
        if kind == "param" and indexes[level] is None:
            return None
        steps.append(("index", str(kind), indexes[level] if kind == "param" else None))
    for member in members:
        steps.append(("member", str(member), None))
    return tuple(steps)


def _element_steps(steps: tuple[_Step, ...]) -> tuple[_Step, ...]:
    """The record's steps without the trailing member path: its storage element."""
    end = len(steps)
    while end > 0 and steps[end - 1][0] == "member":
        end -= 1
    return steps[:end]


def _reads_record_value(scope: _Scope, value: Any, target: tuple[str, tuple[_Step, ...]]) -> bool:
    """Whether ``value`` is the record's own stored value (the ref, or a local assigned from it exactly once)."""
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
    """A debit subtracts from the record's own value; ``amount = cap - used`` may raise it."""
    return _reads_record_value(scope, getattr(binary, "variable_left", None), target)


def _condition_pins_record(scope: _Scope, value: Any, target: tuple[str, tuple[_Step, ...]], depth: int = 0) -> bool:
    """Whether the condition as a whole requires the member to be true, so re-entry reverts: ``require(m)``,
    ``require(m == true)``, or an ``&&`` conjunct of either. ``||``, negation, comparisons against other values,
    or another element all leave a way through.
    """
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
    """A require/assert pinning the same member true on the mandatory path to the flip (dominating it, or earlier in
    its node).
    """
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
    """How this IR clears the record, or ``None``: ``Delete`` of the record or a prefix; assigning zero; subtracting
    from its own value (``r.shares -= x`` or OZ ``_balances[a] = b - amount``); or, behind the flag, zeroing a
    bool member of the same element under a pinning predicate. Not caller-supplied values, struct-wide
    assignments, increments or assembly ``sstore``.
    """
    op = _op(ir)
    target = (base, steps)

    if op == "Delete":
        resolved = scope.path_of(getattr(ir, "variable", None))
        if resolved is None:
            return None
        deleted_base, deleted_steps = resolved
        # Deleting a container clears everything under it.
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

    # Only sound because a mandatory predicate on the member makes re-entry revert.
    if not (FLAG_FLIP_CLEARING_ENABLED and op == "Assignment"):
        return None
    if not _is_false_constant(getattr(ir, "rvalue", None)):
        return None
    if not written or written[-1][0] != "member" or written[:-1] != _element_steps(steps):
        return None
    if _has_mandatory_member_predicate(scope, write_node=node, write_ir_index=ir_index, target=(base, written)):
        return SHAPE_FLAG_FLIP
    return None


class _Site:
    """A site positioned by the chain of call sites reaching it (``path[j]`` is the call in ``units[j]``, the last is
    the site). Keyed on the whole path so a helper called twice has two positions.
    """

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
        # Per call site walking is exponential in wide graphs; exhausting the budget is a refusal.
        self.budget: int = _MAX_WALKED_UNITS


def _is_external_call_ir(ir: Any) -> bool:
    if _op(ir) in _EXTERNAL_CALL_OPS:
        return True
    if _op(ir) != "SolidityCall":
        return False
    return _solidity_call_name(ir).startswith(_CONTROL_TRANSFER_SOLIDITY_PREFIXES)


def _callee_bindings(callee: Any, ir: Any, caller_bindings: dict[int, _Step]) -> dict[int, _Step]:
    """Map the callee's parameters to the call site's values in entry terms; unresolvable ones are ``indeterminate``
    (unmatchable).
    """
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
                # An internal function pointer: the target is chosen at runtime.
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
                # An unimplemented callee's calls weren't ruled out.
                state.incomplete = True
                continue
            key = _unit_key(callee)
            if key in on_path:
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


def _loop_index(unit: Any, cache: dict[int, dict[int, frozenset[int]]]) -> dict[int, frozenset[int]]:
    """``node_id -> loop headers containing it`` by the natural-loop rule (dominated by the header and able to reach
    it via the back edge). Dominance alone would put everything after a loop inside it.
    """
    key = id(unit)
    cached = cache.get(key)
    if cached is not None:
        return cached
    headers = [node for node in _nodes(unit) if _node_type_name(node) == "IFLOOP"]
    # Nodes that can reach each header again (a backward walk).
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
    """Whether the write runs on every path out of ``unit``.

    For a modifier the exit is the ``_;`` placeholder, where the function body and its calls run, so a write after it
    runs after the payout.
    """
    placeholders = [candidate for candidate in _nodes(unit) if _node_type_name(candidate) == "PLACEHOLDER"]
    exits = placeholders or [candidate for candidate in _nodes(unit) if not list(getattr(candidate, "sons", []) or [])]
    if not exits:
        return False
    return all(exit_node is node or _is_dominated_by(exit_node, node) for exit_node in exits)


def _precedes(write: _Site, call: _Site, loops: dict[int, dict[int, frozenset[int]]]) -> tuple[bool, str | None, bool]:
    shared = 0
    while (
        shared < len(write.path)
        and shared < len(call.path)
        and write.path[shared][0] is call.path[shared][0]
        and write.path[shared][1] == call.path[shared][1]
    ):
        shared += 1
    if shared >= len(write.path) or shared >= len(call.path):
        # The write is inside the call or is the call.
        return False, CLEARING_WRITE_DOES_NOT_DOMINATE_CALLS, False
    if shared == 0 and len(write.path) > 1 and len(call.path) > 1:
        # Sibling callees aren't composed through the entry's dominance.
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

    # Below the divergence the write must run whenever the callee is entered, with no loop in between.
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
    """W2 for one ``(function, record)``: proven, or ``not_determined`` with a reason."""
    if assembly_state_access:
        # An unseen write may be the one that matters.
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
    # No external call satisfies the rule vacuously; the question is only asked about flows, which imply a call.
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
    """The record this flow's amount was bound to, or ``None`` (no key published)."""
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
    """Publish W2 on every outbound flow whose amount names a record; absent elsewhere.

    Inbound and routed flows aren't the entry paying, so the question doesn't apply.
    """
    for flow in flows:
        if flow.get("direction") != "out":
            continue
        record = _record_from_flow(flow)
        if record is None:
            continue
        flow["record_ordering"] = prove_record_ordering(function, record, assembly_state_access=assembly_state_access)
