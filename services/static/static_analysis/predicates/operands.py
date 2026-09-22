"""Operand classification — Slither IR values to semantic Operand records."""

from __future__ import annotations

from typing import Any

from eth_utils.crypto import keccak

from ..predicate_types import Operand
from ..provenance import (
    EMPTY,
    TOP,
    ProvenanceMap,
    Source,
    SourceSet,
)
from ..slither_compat import (
    SLITHER_AVAILABLE,
    Assignment,
    Constant,
    Index,
    Member,
    Phi,
    ReferenceVariable,
    SolidityVariable,
    StateVariable,
)

# ---------------------------------------------------------------------------
# Operand classification
# ---------------------------------------------------------------------------


def _source_sort_key(source: Source) -> tuple[str, ...]:
    """Total deterministic order over Source records. ``SourceSet`` is a
    frozenset of string-bearing dataclasses, so its iteration order varies
    with PYTHONHASHSEED — any "pick the first matching source" over it is
    nondeterministic ACROSS PROCESSES (a fold flickered between
    ``ownerOf(uint256)`` and ``_getQueue()`` run to run, flipping the
    public/gated verdict of WithdrawalQueueERC721.approve). Every
    single-source pick must sort by this key first. Deliberately *not* a
    semantic preference: preferring e.g. arg-taking views could attribute a
    nullary authority getter to an inner keyed lookup and manufacture an
    open."""
    return (
        str(source.kind),
        str(source.parameter_index),
        str(source.parameter_name),
        str(source.state_variable_name),
        str(source.member_path),
        str(source.callee),
        str(source.callee_signature),
        str(source.callee_selector),
        str(source.callee_args_digest),
        str(source.constant_value),
        str(source.value_type),
        str(source.computed_kind),
        str(source.block_context_kind),
        str(source.storage_slot),
        _derived_from_sort_key(source.derived_from),
    )


def _published_source_key(source: Source) -> tuple[str, ...]:
    """Order over the fields a Source actually *publishes* to an operand.

    ``callee_args_digest`` is deliberately excluded. It is never emitted, so
    two Sources that differ only in the digest render identically and their
    relative order cannot matter. (The digest is content-stable now —
    ``provenance._digest`` hashes the sorted canonical member keys — so
    including it would no longer vary run to run, but it still orders nothing
    a reader can see.)
    """
    return (
        str(source.kind),
        str(source.parameter_index),
        str(source.parameter_name),
        str(source.state_variable_name),
        str(source.member_path),
        str(source.callee),
        str(source.callee_signature),
        str(source.callee_selector),
        str(source.constant_value),
        str(source.value_type),
        str(source.computed_kind),
        str(source.block_context_kind),
        str(source.storage_slot),
    )


def _derived_from_sort_key(derived_from: frozenset[Source] | None) -> str:
    """Canonical string for ``Source.derived_from`` inside ``_source_sort_key``.

    ``str()`` of a frozenset is iteration-ordered, which is the exact
    nondeterminism ``_source_sort_key`` exists to remove, so the members are
    sorted by their published key first. Recursion terminates at one level:
    every member is stored with ``derived_from=None``.
    """
    if derived_from is None:
        return "None"
    return "|".join(
        "\x1f".join(_published_source_key(origin)) for origin in sorted(derived_from, key=_published_source_key)
    )


def _operand_for_value(value: Any, prov: ProvenanceMap) -> Operand:
    """Translate a Slither IR value's source set into the semantic Operand
    record. Picks the most informative source if multiple are
    present."""
    sources = _sources_for_value(value, prov)
    if not sources:
        op: Operand = {"source": "constant", "constant_value": str(value) if value is not None else ""}
        _attach_value_type(op, value)
        return op
    op = _picked_source_operand(value, sources)
    _attach_element_read(op, value, sources, prov)
    return op


def _picked_source_operand(value: Any, sources: SourceSet) -> Operand:
    """The source the projection publishes, out of everything that reached the
    value. Extracted so the element-read stamp runs once, over whichever source
    won."""
    view_call = _derived_view_call_source(sources)
    if view_call is not None:
        op = _source_to_operand(view_call)
        _attach_state_constant_value(op, value)
        return op
    # Priority: msg_sender > signature_recovery > parameter > state_variable
    # > view_call > external_call > computed > constant > block_context > top.
    priority = (
        "msg_sender",
        "tx_origin",
        "signature_recovery",
        "self_address",  # ``address(this)`` self-call gate (auth-shaped)
        "parameter",
        "state_variable",
        "view_call",
        "external_call",
        "computed",
        "constant",
        "block_context",
        "top",
    )
    for kind in priority:
        matches = sorted((s for s in sources if s.kind == kind), key=_source_sort_key)
        if kind == "state_variable":
            # Stable sort: member-path depth first, sort-key order within ties.
            matches = sorted(matches, key=lambda source: len(getattr(source, "member_path", ()) or ()), reverse=True)
        for s in matches:
            op = _source_to_operand(s)
            _attach_state_constant_value(op, value)
            return op
    # Fallback: any source (deterministically the sort-key minimum).
    op = _source_to_operand(min(sources, key=_source_sort_key))
    _attach_state_constant_value(op, value)
    return op


# Deeper nesting than ``record.member.member`` is a coverage question of its own
# and is not answered here, so it publishes nothing rather than a truncated path.
_MAX_ELEMENT_MEMBER_DEPTH = 2
# An access chain is straight-line ``Index``/``Member`` IR; the cap only bounds a
# malformed self-referential one.
_ELEMENT_CHAIN_CAP = 8


def _attach_element_read(op: Operand, value: Any, sources: SourceSet, prov: ProvenanceMap) -> None:
    """Stamp the three ``element_*`` facts when ``value`` is one resolved storage
    element read, and stamp nothing at all otherwise.

    All three or none: they describe a single cell, so a chain that pins a base
    but not its key must publish no cell — the consumer joining an amount to a
    guard has no way to recover the missing half and would otherwise join on the
    base name alone.

    All-or-none is also what keeps ``_operand_sort_key`` total across these
    fields. Its presence flag for ``element_key_param_index`` cannot on its own
    separate an operand carrying no element read from one whose key is a proven
    ``None`` — both render as the absent flag — and it is
    ``element_base_variable``'s slot, present exactly when the other two are,
    that discriminates them. A later unit that relaxes all-or-none collapses
    that distinction in the published order and owes the sort key a fix.
    """
    fields = _element_read_fields(value, sources, prov)
    if fields is None:
        return
    base_variable, member_path, key_param_index = fields
    op["element_base_variable"] = base_variable
    op["element_member_path"] = member_path
    op["element_key_param_index"] = key_param_index


def _element_read_fields(
    value: Any, sources: SourceSet, prov: ProvenanceMap
) -> tuple[str, list[str], int | None] | None:
    if not SLITHER_AVAILABLE or not isinstance(value, ReferenceVariable):
        return None
    chain = _element_access_chain(value)
    if chain is None:
        return None
    base, member_path, keys = chain
    # Exactly one key level: the published slot names ONE level, and a second
    # would have nowhere to land — an ambiguous cell, not a narrower one.
    if len(keys) != 1 or len(member_path) > _MAX_ELEMENT_MEMBER_DEPTH:
        return None
    canonical = getattr(base, "canonical_name", None)
    if not canonical:
        return None
    # Provenance has to have seen the read the IR walk just described: one base
    # declaration, and a state-variable source carrying exactly this member path.
    # A chain merged through a phi, or one whose base saturated to top, fails
    # here instead of publishing a cell nothing proves was read.
    if {source.state_variable_name for source in sources if source.kind == "state_variable"} != {base.name}:
        return None
    if not any(source.kind == "state_variable" and tuple(source.member_path) == member_path for source in sources):
        return None
    resolved, key_param_index = _element_key_param_index(keys[0], prov)
    if not resolved or _key_definition_is_merged(keys[0], value):
        return None
    return str(canonical), list(member_path), key_param_index


def _element_access_chain(value: Any) -> tuple[Any, tuple[str, ...], list[Any]] | None:
    """Walk a reference back through its defining ``Index``/``Member`` IR to the
    state variable it reads, collecting the member path and the index keys.

    ``None`` for anything else on the chain — a storage-pointer local, an
    assignment, a type conversion, a reference whose definition is not singular —
    because a read this walk cannot follow is a read it cannot name.
    """
    member_path: list[str] = []
    keys: list[Any] = []
    current = value
    for _ in range(_ELEMENT_CHAIN_CAP):
        if not isinstance(current, ReferenceVariable):
            break
        ir = _defining_reference_ir(current)
        if isinstance(ir, Member):
            field = getattr(ir.variable_right, "value", None) or getattr(ir.variable_right, "name", None)
            if not isinstance(field, str) or not field:
                return None
            member_path.append(field)
            current = ir.variable_left
        elif isinstance(ir, Index):
            keys.append(ir.variable_right)
            current = ir.variable_left
        else:
            return None
    else:
        return None
    if not isinstance(current, StateVariable):
        return None
    member_path.reverse()
    keys.reverse()
    return current, tuple(member_path), keys


def _defining_reference_ir(ref: Any) -> Any | None:
    """The ONE IR in the reference's home node whose lvalue IS this reference.

    The uniqueness rule is what makes the answer safe: a reference with two
    definitions in its node is a chain this walk cannot read, so it yields
    nothing rather than the first candidate. Identity rather than name because
    identity is what "this reference" means; ``REF_n`` names carry no promise.
    """
    node = getattr(ref, "node", None)
    if node is None:
        return None
    defining = [ir for ir in (getattr(node, "irs_ssa", None) or ()) if getattr(ir, "lvalue", None) is ref]
    return defining[0] if len(defining) == 1 else None


def _key_definition_is_merged(key: Any, value: Any) -> bool:
    """True when the index key's SSA definition chain passes through a ``Phi``
    that joins more than one value — ``recs[flag ? a : b]`` and its if/else form.

    Structural on purpose, because the key's SOURCE SET does not answer this and
    cannot be made to: provenance folds a merged local back to a single source,
    so ``recs[flag ? a : b]`` reports the one parameter ``b`` and the cardinality
    test that refuses ``recs[_bidId + 1]`` never fires. Publishing that slot
    would name a cell the read is only sometimes keyed by, and
    ``balances[flag ? msg.sender : who]`` would publish a possibly-caller-keyed
    cell as parameter-keyed — inverting the one distinction these fields exist
    to carry.

    Refuses outright when the containing declaration cannot be reached: a key
    whose definitions cannot be enumerated is not a proven key. The BASE chain
    needs no equivalent test — ``_element_access_chain`` follows only
    ``Index``/``Member``, so a ``Phi`` on the base stops the walk before any cell
    is named.
    """
    definitions = _ssa_definitions(value)
    if definitions is None:
        return True
    seen: set[int] = set()
    pending = [key]
    while pending:
        current = pending.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        defining = definitions.get(id(current)) or []
        if len(defining) > 1:
            return True
        if not defining:
            continue
        ir = defining[0]
        if isinstance(ir, Phi):
            rvalues = list(getattr(ir, "rvalues", None) or ())
            if len({id(rvalue) for rvalue in rvalues}) > 1:
                return True
            pending.extend(rvalues)
        elif isinstance(ir, Assignment):
            pending.append(getattr(ir, "rvalue", None))
    return False


def _ssa_definitions(value: Any) -> dict[int, list[Any]] | None:
    """Every SSA lvalue in the reference's containing declaration and its
    modifiers, mapped by identity to the IRs that define it.

    ``None`` when the declaration cannot be reached at all, which the caller
    reads as a refusal rather than as an empty answer.
    """
    node = getattr(value, "node", None)
    container = getattr(node, "function", None) if node is not None else None
    if container is None:
        return None
    declarations = [container]
    declarations.extend(getattr(container, "modifiers", []) or [])
    definitions: dict[int, list[Any]] = {}
    for declaration in declarations:
        for declaration_node in getattr(declaration, "nodes", []) or []:
            for ir in getattr(declaration_node, "irs_ssa", None) or ():
                lvalue = getattr(ir, "lvalue", None)
                if lvalue is not None:
                    definitions.setdefault(id(lvalue), []).append(ir)
    return definitions


def _element_key_param_index(key: Any, prov: ProvenanceMap) -> tuple[bool, int | None]:
    """``(resolved, slot)`` for an index key: the entry-parameter slot it came
    from, or ``None`` for a key proven to be ``msg.sender``.

    One source and one source only. ``bids[_bidId + 1]`` carries the parameter's
    own source alongside the arithmetic, and reading the slot off it would
    publish agreement with ``bids[_bidId]`` over two different cells. ``None`` is
    reserved for the caller: it is the one non-parameter key whose identity is
    proven rather than merely unresolved, and a consumer reads it as "no entry
    parameter names this cell", not as "the key is unknown".
    """
    key_sources = _sources_for_value(key, prov)
    if len(key_sources) != 1:
        return (False, None)
    (source,) = tuple(key_sources)
    if source.kind == "parameter" and source.parameter_index is not None:
        return (True, source.parameter_index)
    if source.kind == "msg_sender":
        return (True, None)
    return (False, None)


def _derived_view_call_source(sources: SourceSet) -> Source | None:
    if any(s.kind in ("msg_sender", "tx_origin", "signature_recovery", "root_caller") for s in sources):
        return None
    has_state = any(s.kind == "state_variable" for s in sources)
    has_parameter = any(s.kind == "parameter" for s in sources)
    if not has_state or not has_parameter:
        return None
    return min((s for s in sources if s.kind == "view_call"), key=_source_sort_key, default=None)


def _source_to_operand(source: Source, *, nested: bool = False) -> Operand:
    op: Operand = {"source": source.kind}
    if source.parameter_index is not None:
        op["parameter_index"] = source.parameter_index
    if source.parameter_name is not None:
        op["parameter_name"] = source.parameter_name
    if source.state_variable_name is not None:
        op["state_variable_name"] = source.state_variable_name
    if getattr(source, "member_path", None):
        op["member_path"] = list(source.member_path)
    if source.callee is not None:
        op["callee"] = source.callee
    if source.callee_signature is not None:
        op["callee_signature"] = source.callee_signature
    if source.callee_selector is not None:
        op["callee_selector"] = source.callee_selector
    if getattr(source, "storage_slot", None) is not None:
        op["storage_slot"] = source.storage_slot
    if source.constant_value is not None:
        op["constant_value"] = source.constant_value
    if getattr(source, "value_type", None) is not None:
        op["value_type"] = source.value_type
    if source.computed_kind is not None:
        op["computed_kind"] = source.computed_kind
    if source.block_context_kind is not None:
        op["block_context_kind"] = source.block_context_kind
    if source.kind in ("computed", "view_call", "external_call") and not nested:
        # Always emitted on a computed / view_call / external_call operand, and
        # only there, so absence is "the question does not apply" rather than a
        # silent third meaning. (view_call/external_call are included because
        # the call's argument provenance — the caller, in the RoleRegistry
        # shape — must survive onto the operand; the digest alone is opaque.)
        # ``null`` is not-determined; a list (possibly empty) is determined.
        # ``nested`` renders the members, whose own ``derived_from`` was
        # stripped by ``arg_origins`` after being spliced into this list —
        # emitting ``null`` there would read as an unknown that isn't one.
        op["derived_from"] = (
            None
            if source.derived_from is None
            else [
                _source_to_operand(origin, nested=True)
                for origin in sorted(source.derived_from, key=_published_source_key)
            ]
        )
    return op


def _attach_state_constant_value(op: Operand, value: Any) -> None:
    if op.get("source") != "state_variable":
        return
    constant_value = _state_variable_bytes32_constant_value(value)
    if constant_value is not None:
        op["constant_value"] = constant_value


def _attach_value_type(op: Operand, value: Any) -> None:
    type_obj = getattr(value, "type", None)
    if type_obj is None:
        return
    type_name = getattr(type_obj, "name", None) or str(type_obj)
    if type_name:
        op["value_type"] = type_name


def _state_variable_bytes32_constant_value(value: Any) -> str | None:
    variable = value
    nsv = getattr(value, "non_ssa_version", None)
    if nsv is not None:
        variable = nsv
    if not getattr(variable, "is_constant", False):
        return None
    if str(getattr(variable, "type", "")) != "bytes32":
        return None
    return _bytes32_constant_expression_value(getattr(variable, "expression", None))


def _bytes32_constant_expression_value(expression: Any) -> str | None:
    literal = getattr(expression, "value", None)
    if literal is not None:
        return _coerce_bytes32_hex(literal)

    called = str(getattr(expression, "called", ""))
    if not called.startswith("keccak256"):
        return None
    args = list(getattr(expression, "arguments", []) or [])
    if len(args) != 1:
        return None
    text = _single_string_literal(args[0])
    if text is None:
        return None
    return "0x" + keccak(text=text).hex()


def _single_string_literal(expression: Any) -> str | None:
    value = getattr(expression, "value", None)
    if isinstance(value, str):
        return value

    called = str(getattr(expression, "called", ""))
    if called != "abi.encodePacked":
        return None
    args = list(getattr(expression, "arguments", []) or [])
    if len(args) != 1:
        return None
    value = getattr(args[0], "value", None)
    return value if isinstance(value, str) else None


def _coerce_bytes32_hex(value: Any) -> str | None:
    if isinstance(value, int):
        if value < 0:
            return None
        return "0x" + value.to_bytes(32, "big").hex()
    if not isinstance(value, str):
        return None
    raw = value.strip().lower()
    if not raw.startswith("0x"):
        return None
    body = raw[2:]
    if len(body) > 64:
        return None
    try:
        int(body or "0", 16)
    except ValueError:
        return None
    return "0x" + body.rjust(64, "0")


def _value_type_name(value: Any) -> str | None:
    type_obj = getattr(value, "type", None)
    if type_obj is None:
        return None
    type_name = getattr(type_obj, "name", None) or str(type_obj)
    return type_name or None


def _sources_for_value(value: Any, prov: ProvenanceMap) -> SourceSet:
    """Read provenance for a Slither value.

    For SolidityVariables (msg.sender / tx.origin / block.*) we
    classify on-demand — they don't appear as SSA lvalues in the
    provenance map. For StateVariables we emit a state_variable
    source directly. For Constants we emit a constant source. For
    everything else (LocalIRVariables, ReferenceVariables, TMPs,
    Phi outputs) we look up the name in the provenance map.
    """
    if value is None:
        return EMPTY
    if isinstance(value, Constant):
        return frozenset(
            {
                Source(
                    kind="constant",
                    constant_value=str(value.value),
                    value_type=_value_type_name(value),
                )
            }
        )
    if isinstance(value, SolidityVariable):
        return _classify_solidity_variable(value)
    if isinstance(value, StateVariable):
        return frozenset({Source(kind="state_variable", state_variable_name=value.name)})
    name = getattr(value, "name", None)
    if name is None:
        return EMPTY
    return prov.get(name)


def _classify_solidity_variable(var: Any) -> SourceSet:
    """Same logic as ProvenanceEngine._classify_solidity_variable but
    re-implemented here so the predicate builder can call it on
    operands without needing the engine instance."""
    name = getattr(var, "name", "")
    if name == "msg.sender":
        return frozenset({Source(kind="msg_sender")})
    if name == "tx.origin":
        return frozenset({Source(kind="tx_origin")})
    if name in (
        "block.timestamp",
        "block.number",
        "block.chainid",
        "block.coinbase",
        "block.difficulty",
        "block.gaslimit",
        "now",
        "block.basefee",
        "block.prevrandao",
    ):
        return frozenset(
            {
                Source(
                    kind="block_context",
                    block_context_kind=name.split(".", 1)[-1] if "." in name else name,
                )
            }
        )
    if name in ("msg.value", "msg.data", "msg.sig", "msg.gas"):
        return frozenset({Source(kind="computed", computed_kind=name)})
    return TOP


def _sources_from_destination(ir: Any, prov: ProvenanceMap) -> SourceSet:
    """For a HighLevelCall, return the destination (call target)'s
    provenance. Slither exposes this as ``destination``."""
    dest = getattr(ir, "destination", None)
    return _sources_for_value(dest, prov) if dest is not None else EMPTY
