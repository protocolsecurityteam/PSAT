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


def _source_sort_key(source: Source) -> tuple[str, ...]:
    """Total deterministic order over sources.

    A ``SourceSet``'s iteration order varies with PYTHONHASHSEED, which once flipped WithdrawalQueueERC721.approve
    between public and gated across runs, so every single-source pick sorts by this. Deliberately not a semantic
    preference.
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
        str(source.callee_args_digest),
        str(source.constant_value),
        str(source.value_type),
        str(source.computed_kind),
        str(source.block_context_kind),
        str(source.storage_slot),
        _derived_from_sort_key(source.derived_from),
    )


def _published_source_key(source: Source) -> tuple[str, ...]:
    """Order over the fields a Source publishes; ``callee_args_digest`` is never emitted, so it can't matter."""
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
    """Canonical string for ``derived_from`` (a frozenset's ``str`` is iteration-ordered).

    Members have ``derived_from=None``, so one level.
    """
    if derived_from is None:
        return "None"
    return "|".join(
        "\x1f".join(_published_source_key(origin)) for origin in sorted(derived_from, key=_published_source_key)
    )


def _operand_for_value(value: Any, prov: ProvenanceMap) -> Operand:
    """A value's source set as an Operand, picking the most informative source."""
    sources = _sources_for_value(value, prov)
    if not sources:
        op: Operand = {"source": "constant", "constant_value": str(value) if value is not None else ""}
        _attach_value_type(op, value)
        return op
    op = _picked_source_operand(value, sources)
    _attach_element_read(op, value, sources, prov)
    return op


def _picked_source_operand(value: Any, sources: SourceSet) -> Operand:
    """The published source; the element-read stamp runs once over it."""
    view_call = _derived_view_call_source(sources)
    if view_call is not None:
        op = _source_to_operand(view_call)
        _attach_state_constant_value(op, value)
        return op
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
            matches = sorted(matches, key=lambda source: len(getattr(source, "member_path", ()) or ()), reverse=True)
        for s in matches:
            op = _source_to_operand(s)
            _attach_state_constant_value(op, value)
            return op
    op = _source_to_operand(min(sources, key=_source_sort_key))
    _attach_state_constant_value(op, value)
    return op


# Deeper nesting publishes nothing rather than a truncated path.
_MAX_ELEMENT_MEMBER_DEPTH = 2
# Only bounds a malformed self-referential chain.
_ELEMENT_CHAIN_CAP = 8


def _attach_element_read(op: Operand, value: Any, sources: SourceSet, prov: ProvenanceMap) -> None:
    """Stamp the three ``element_*`` facts when ``value`` is one resolved storage element read, else nothing.

    All or none: a base without its key would let a consumer join on the base alone. It also keeps ``_operand_sort_key``
    total: ``element_base_variable`` distinguishes "no element read" from a key proven ``None``.
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
    # One key level only; a second has nowhere to land.
    if len(keys) != 1 or len(member_path) > _MAX_ELEMENT_MEMBER_DEPTH:
        return None
    canonical = getattr(base, "canonical_name", None)
    if not canonical:
        return None
    # Provenance must agree: one base and a state-variable source with exactly this path (a phi-merged or saturated
    # chain fails).
    if {source.state_variable_name for source in sources if source.kind == "state_variable"} != {base.name}:
        return None
    if not any(source.kind == "state_variable" and tuple(source.member_path) == member_path for source in sources):
        return None
    resolved, key_param_index = _element_key_param_index(keys[0], prov)
    if not resolved or _key_definition_is_merged(keys[0], value):
        return None
    return str(canonical), list(member_path), key_param_index


def _element_access_chain(value: Any) -> tuple[Any, tuple[str, ...], list[Any]] | None:
    """Walk a reference through ``Index``/``Member`` IR to its state variable, collecting member path and keys;
    ``None`` for anything else on the chain.
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
    """The one IR in the reference's node whose lvalue is this reference (by identity); two definitions yield
    nothing.
    """
    node = getattr(ref, "node", None)
    if node is None:
        return None
    defining = [ir for ir in (getattr(node, "irs_ssa", None) or ()) if getattr(ir, "lvalue", None) is ref]
    return defining[0] if len(defining) == 1 else None


def _key_definition_is_merged(key: Any, value: Any) -> bool:
    """True when the index key's SSA chain passes through a multi-value ``Phi`` (``recs[flag ? a : b]``).

    Structural because provenance folds a merged local to one source, so the arithmetic refusal never fires, and
    ``balances[flag ? msg.sender : who]`` would publish a possibly-caller-keyed cell as parameter-keyed. Refuses when
    the declaration can't be reached. The base needs no such check (``_element_access_chain`` stops at a Phi).
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
    """Every SSA lvalue in the reference's declaration and modifiers, by identity, to its defining IRs; ``None`` if
    unreachable (a refusal).
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
    """``(resolved, slot)`` for a key: its entry-parameter slot, or ``None`` for a key proven to be ``msg.sender``.

    Exactly one source: ``bids[_bidId + 1]`` carries the parameter's source too and would falsely agree with
    ``bids[_bidId]``. ``None`` means "no entry parameter names this cell", not unknown.
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
        # Emitted on every computed/view_call/external_call operand and only there, so absence means "doesn't apply".
        # Call operands keep argument provenance (the caller, in the RoleRegistry shape). ``null`` is not determined; a
        # list is determined.
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
    """Provenance for a Slither value: Solidity variables classified on demand (not SSA lvalues), state variables and
    constants directly, everything else looked up in the map.
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
    """Mirror of ProvenanceEngine._classify_solidity_variable, usable without an engine."""
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
    """Provenance of a HighLevelCall's ``destination``."""
    dest = getattr(ir, "destination", None)
    return _sources_for_value(dest, prov) if dest is not None else EMPTY
