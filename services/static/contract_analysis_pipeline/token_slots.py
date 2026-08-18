"""Static derivation of token-precondition storage slots for the effects stage.

The effects stage proves pause behaviour on an anvil fork by diffing entry
points pre/post pause. Token entry points (``transferFrom`` etc.) revert
pre-pause because the simulated caller has no balance/allowance/shares/ownership,
so they never reach the pause gate and the verdict degrades to unknown. To let
the fork seed those preconditions with ``anvil_setStorageAt``, the fork needs the
storage *base slot* of the backing mapping — a fact of the layout, i.e. of the
bytecode, so it rides the existing cross-chain artifact reuse unchanged.

That derivation needs a live Slither parse, which the effects stage does not have
(it runs off the persisted artifact). So this pass runs at STATIC time and stamps
the derived slots into the ``effects`` artifact under the top-level ``token_slots``
key. Each entry names a public/external VIEW getter that returns the raw mapping
value for its key(s) — the effects side seeds ``base_slot`` then reads that getter
back with strict equality, so the getter MUST be a direct read of the mapping, not
a computed/derived value (a rebasing ``balanceOf = shares * rate`` never qualifies).

The rule of the pass is: never guess. Anything uncertain is skipped; absence of an
entry degrades to today's behaviour, and the effects-side read-back is a further
net against any residual derivation error. Two layout standards are supported:

  * ``storage_layout`` — the mapping is a plain contract state variable; its base
    slot comes from Slither's storage layout.
  * ``oz_v5_namespaced`` — the mapping is a member of an ERC-7201 namespaced
    struct (OZ v5 ``ERC20Storage``: ``_balances`` then ``_allowances`` …); the
    struct base is the folded ``*StorageLocation`` bytes32 constant and the member
    offset is walked with standard Solidity slot rules.

Vyper units use different slot math and are skipped entirely.
"""

from __future__ import annotations

import logging
from typing import Any

from .slither_compat import (
    SLITHER_AVAILABLE,
    Assignment,
    Binary,
    BinaryType,
    Index,
    InternalCall,
    LibraryCall,
    MappingType,
    Member,
    Return,
    StateVariable,
    UserDefinedType,
)

logger = logging.getLogger(__name__)


# Family of semantic getters this pass anchors on, keyed by canonical signature.
# The role/key_kind are fixed per signature (a semantic anchor, not a name guess).
# ``key_types`` is the flattened key-type tuple the backing mapping must have.
_FAMILY: dict[str, tuple[str, str, tuple[str, ...]]] = {
    "balanceOf(address)": ("balance", "address", ("address",)),
    "allowance(address,address)": ("allowance", "address_address", ("address", "address")),
    "sharesOf(address)": ("shares", "address", ("address",)),
    "shares(address)": ("shares", "address", ("address",)),
    "ownerOf(uint256)": ("owner", "uint256", ("uint256",)),
}

# Deterministic emission order.
_ROLE_ORDER = {"balance": 0, "allowance": 1, "shares": 2, "owner": 3}

_ADDRESS_TYPES = {"address", "address payable"}

# Binary IR types that do NOT transform the mapping value (comparisons /
# short-circuit boolean ops, i.e. the kind that appears in a require guard). Any
# other Binary in the getter's dataflow means the returned value is computed, not
# the raw mapping read the read-back anchor requires.
_NON_TRANSFORMING_BINARY: frozenset[Any] = frozenset(
    getattr(BinaryType, name)
    for name in ("EQUAL", "NOT_EQUAL", "LESS", "LESS_EQUAL", "GREATER", "GREATER_EQUAL", "ANDAND", "OROR")
    if SLITHER_AVAILABLE and hasattr(BinaryType, name)
)

_MAX_TRACE_DEPTH = 3


def derive_token_slots(contract: Any) -> dict[str, Any] | None:
    """Return ``{"entries": [...]}`` for ``contract``'s token-precondition
    mappings, or ``None`` when nothing was derived with certainty.

    Never raises: any Slither edge degrades to ``None`` (the key is then omitted
    and the effects stage keeps its current behaviour)."""
    if not SLITHER_AVAILABLE:
        return None
    try:
        cu = getattr(contract, "compilation_unit", None)
        if cu is None or _is_vyper(cu):
            return None

        entries: list[dict[str, Any]] = []
        seen_roles: set[str] = set()

        # Auto-generated public-mapping getters first: a public mapping is a
        # direct read by construction, and Slither does not surface its getter
        # as an entry-point function, so it must be matched structurally.
        for var in _public_mapping_state_vars(contract):
            fam = _family_for_public_mapping(var)
            if fam is None or fam[1] in seen_roles:
                continue
            sig, role, key_kind = fam
            entry = _plain_entry(contract, var, sig, role, key_kind)
            if entry is not None:
                entries.append(entry)
                seen_roles.add(role)

        # Handwritten getters: a real view function whose canonical signature is
        # in the family and whose single return is a direct mapping index.
        for fn in _candidate_view_functions(contract):
            fam = _FAMILY.get(_full_name(fn))
            if fam is None or fam[0] in seen_roles:
                continue
            role, key_kind, key_types = fam
            entry = _handwritten_entry(contract, fn, role, key_kind, key_types)
            if entry is not None:
                entries.append(entry)
                seen_roles.add(role)

        if not entries:
            return None
        entries.sort(key=lambda e: _ROLE_ORDER.get(e["role"], 99))
        return {"entries": entries}
    except Exception:  # pragma: no cover - defensive; never break the artifact
        logger.debug("token-slot derivation failed", exc_info=True)
        return None


# ---------------------------------------------------------------------------
# Compilation-unit / contract introspection
# ---------------------------------------------------------------------------


def _is_vyper(cu: Any) -> bool:
    if bool(getattr(cu, "is_vyper", False)):
        return True
    lang = str(getattr(cu, "language", "") or "").lower()
    return "vyper" in lang


def _public_mapping_state_vars(contract: Any) -> list[Any]:
    out: list[Any] = []
    variables = getattr(contract, "state_variables_ordered", None) or getattr(contract, "state_variables", []) or []
    for var in variables:
        if getattr(var, "visibility", None) != "public":
            continue
        if getattr(var, "is_constant", False) or getattr(var, "is_immutable", False):
            continue
        if isinstance(getattr(var, "type", None), MappingType):
            out.append(var)
    return out


def _candidate_view_functions(contract: Any) -> list[Any]:
    out: list[Any] = []
    for fn in getattr(contract, "functions_entry_points", []) or []:
        if getattr(fn, "visibility", None) not in ("public", "external"):
            continue
        if not (getattr(fn, "view", False) or getattr(fn, "pure", False)):
            continue
        if getattr(fn, "is_constructor", False):
            continue
        out.append(fn)
    return out


def _full_name(fn: Any) -> str:
    return str(getattr(fn, "full_name", "") or "")


# ---------------------------------------------------------------------------
# Mapping shape
# ---------------------------------------------------------------------------


def _elem_name(type_obj: Any) -> str:
    return str(getattr(type_obj, "name", None) or type_obj)


def _flatten_mapping(map_type: Any) -> tuple[tuple[str, ...], Any] | None:
    """``(flattened key-type names, terminal value type)`` for a (possibly
    nested) mapping, or ``None`` if ``map_type`` isn't a mapping."""
    if not isinstance(map_type, MappingType):
        return None
    keys: list[str] = []
    current: Any = map_type
    while isinstance(current, MappingType):
        keys.append(_elem_name(current.type_from))
        current = current.type_to
    return tuple(keys), current


def _value_ok_for_role(value_type: Any, role: str) -> bool:
    name = _elem_name(value_type)
    if role == "owner":
        return name in _ADDRESS_TYPES
    return name.startswith("uint")  # balance / allowance / shares are unsigned amounts


def _mapping_matches(map_type: Any, key_types: tuple[str, ...], role: str) -> bool:
    flat = _flatten_mapping(map_type)
    if flat is None:
        return False
    keys, value = flat
    return keys == key_types and _value_ok_for_role(value, role)


def _family_for_public_mapping(var: Any) -> tuple[str, str, str] | None:
    """``(canonical getter signature, role, key_kind)`` if ``var``'s
    auto-generated getter is in the family and its value shape fits."""
    flat = _flatten_mapping(getattr(var, "type", None))
    if flat is None:
        return None
    keys, _value = flat
    name = getattr(var, "name", None)
    if not name:
        return None
    sig = f"{name}({','.join(keys)})"
    fam = _FAMILY.get(sig)
    if fam is None:
        return None
    role, key_kind, key_types = fam
    if not _mapping_matches(getattr(var, "type", None), key_types, role):
        return None
    return sig, role, key_kind


# ---------------------------------------------------------------------------
# storage_layout path
# ---------------------------------------------------------------------------


def _storage_layout_for(contract: Any, state_var: Any) -> tuple[int, int] | None:
    cu = getattr(contract, "compilation_unit", None)
    if cu is None:
        return None
    try:
        return cu.storage_layout_of(contract, state_var)
    except Exception:
        try:
            cu.compute_storage_layout()
            return cu.storage_layout_of(contract, state_var)
        except Exception:
            logger.debug("storage layout unavailable for %s", getattr(state_var, "name", "?"), exc_info=True)
            return None


def _base_slot_hex(slot_index: int) -> str:
    return "0x" + format(int(slot_index), "064x")


def _plain_entry(contract: Any, var: Any, sig: str, role: str, key_kind: str) -> dict[str, Any] | None:
    layout = _storage_layout_for(contract, var)
    if layout is None:
        return None
    slot_index, byte_offset = layout
    if int(byte_offset) != 0:  # a mapping always sits at offset 0; anything else is wrong
        return None
    return {
        "getter": sig,
        "role": role,
        "key_kind": key_kind,
        "base_slot": _base_slot_hex(slot_index),
        "derivation": "storage_layout",
        "variable": getattr(var, "name", None),
    }


# ---------------------------------------------------------------------------
# Handwritten getters: return-value dataflow
# ---------------------------------------------------------------------------


def _defining_map(fn: Any) -> dict[str, Any]:
    """``{lvalue_name: first defining IR}`` for a function's IR."""
    out: dict[str, Any] = {}
    for node in getattr(fn, "nodes", []) or []:
        for ir in getattr(node, "irs", []) or []:
            lvalue = getattr(ir, "lvalue", None)
            name = getattr(lvalue, "name", None)
            if name and name not in out:
                out[name] = ir
    return out


def _defining_of(dm: dict[str, Any], obj: Any) -> Any:
    name = getattr(obj, "name", None)
    return dm.get(name) if isinstance(name, str) else None


def _single_return_value(fn: Any) -> Any | None:
    values: list[Any] = []
    for node in getattr(fn, "nodes", []) or []:
        for ir in getattr(node, "irs", []) or []:
            if isinstance(ir, Return):
                values.extend(getattr(ir, "values", []) or [])
    return values[0] if len(values) == 1 else None


def _trace_return_to_index(fn: Any, depth: int = 0) -> tuple[Any, Any] | None:
    """``(Index IR, owning function)`` for the mapping read whose value the
    function directly returns, following a short chain of trivial internal
    wrappers (up to ``_MAX_TRACE_DEPTH``; the OZ ``ownerOf → _requireOwned →
    _owners[id]`` shape). ``None`` if the return isn't a direct mapping index."""
    if depth > _MAX_TRACE_DEPTH:
        return None
    value = _single_return_value(fn)
    if value is None:
        return None
    return _resolve_value_to_index(value, fn, _defining_map(fn), depth)


def _resolve_value_to_index(value: Any, fn: Any, dm: dict[str, Any], depth: int) -> tuple[Any, Any] | None:
    defining = _defining_of(dm, value)
    if isinstance(defining, Index):
        return defining, fn
    if isinstance(defining, Assignment):
        return _resolve_value_to_index(getattr(defining, "rvalue", None), fn, dm, depth)
    if isinstance(defining, (InternalCall, LibraryCall)):
        callee = getattr(defining, "function", None)
        if callee is not None and getattr(callee, "nodes", None):
            return _trace_return_to_index(callee, depth + 1)
    return None


def _index_root(index_ir: Any, dm: dict[str, Any]) -> tuple[Any, Any]:
    """Walk an Index chain's ``variable_left`` back to its base. Returns
    ``(base_operand, base_defining_ir)``."""
    current = index_ir
    seen: set[int] = set()
    while isinstance(current, Index):
        left = getattr(current, "variable_left", None)
        defining = _defining_of(dm, left)
        if isinstance(defining, Index) and id(defining) not in seen:
            seen.add(id(defining))
            current = defining
            continue
        return left, defining
    return None, None


def _has_value_transforming_arithmetic(fn: Any, depth: int = 0, seen: set[Any] | None = None) -> bool:
    """Any Binary op other than a comparison/boolean guard — in ``fn`` or an
    internal/library function it calls — means the returned value is computed."""
    if seen is None:
        seen = set()
    key = getattr(fn, "canonical_name", None) or id(fn)
    if key in seen or depth > _MAX_TRACE_DEPTH:
        return False
    seen.add(key)
    for node in getattr(fn, "nodes", []) or []:
        for ir in getattr(node, "irs", []) or []:
            if isinstance(ir, Binary) and getattr(ir, "type", None) not in _NON_TRANSFORMING_BINARY:
                return True
            if isinstance(ir, (InternalCall, LibraryCall)):
                callee = getattr(ir, "function", None)
                if callee is not None and getattr(callee, "nodes", None):
                    if _has_value_transforming_arithmetic(callee, depth + 1, seen):
                        return True
    return False


def _handwritten_entry(
    contract: Any, fn: Any, role: str, key_kind: str, key_types: tuple[str, ...]
) -> dict[str, Any] | None:
    traced = _trace_return_to_index(fn)
    if traced is None:
        return None
    if _has_value_transforming_arithmetic(fn):
        return None
    index_ir, owning_fn = traced
    base, base_defining = _index_root(index_ir, _defining_map(owning_fn))

    if isinstance(base, StateVariable):
        return _handwritten_plain_entry(contract, fn, base, role, key_kind, key_types)
    if isinstance(base_defining, Member):
        return _handwritten_namespaced_entry(fn, owning_fn, base_defining, role, key_kind, key_types)
    return None


def _handwritten_plain_entry(
    contract: Any, fn: Any, var: Any, role: str, key_kind: str, key_types: tuple[str, ...]
) -> dict[str, Any] | None:
    # The getter must read exactly this one mapping — nothing else feeds the
    # returned value (a second read is a computed getter, not a raw read).
    reads = _state_variables_read(fn)
    if len(reads) != 1 or reads[0] is not var:
        return None
    if not _mapping_matches(getattr(var, "type", None), key_types, role):
        return None
    return _plain_entry(contract, var, _full_name(fn), role, key_kind)


def _state_variables_read(fn: Any) -> list[Any]:
    reader = getattr(fn, "all_state_variables_read", None)
    if reader is None:
        return []
    try:
        result: Any = reader() if callable(reader) else reader
    except Exception:  # pragma: no cover - slither edge
        return []
    return list(result or [])


# ---------------------------------------------------------------------------
# oz_v5_namespaced path
# ---------------------------------------------------------------------------


def _handwritten_namespaced_entry(
    fn: Any, owning_fn: Any, member_ir: Any, role: str, key_kind: str, key_types: tuple[str, ...]
) -> dict[str, Any] | None:
    member_name = getattr(getattr(member_ir, "variable_right", None), "name", None)
    struct_local = getattr(member_ir, "variable_left", None)
    if not member_name or struct_local is None:
        return None

    struct = _struct_of_local(struct_local)
    if struct is None:
        return None

    member_type = _struct_member_type(struct, member_name)
    if member_type is None or not _mapping_matches(member_type, key_types, role):
        return None

    const_base = _namespaced_struct_base(struct_local, owning_fn)
    if const_base is None:
        return None

    slot_offset = _struct_member_slot_offset(struct, member_name)
    if slot_offset is None:
        return None

    return {
        "getter": _full_name(fn),
        "role": role,
        "key_kind": key_kind,
        "base_slot": _base_slot_hex(const_base + slot_offset),
        "derivation": "oz_v5_namespaced",
        "variable": member_name,
    }


def _struct_of_local(local_var: Any) -> Any | None:
    type_obj = getattr(local_var, "type", None)
    if isinstance(type_obj, UserDefinedType):
        inner = getattr(type_obj, "type", None)
        if getattr(inner, "elems_ordered", None) is not None:
            return inner
    return None


def _struct_member_type(struct: Any, member_name: str) -> Any | None:
    for elem in getattr(struct, "elems_ordered", []) or []:
        if getattr(elem, "name", None) == member_name:
            return getattr(elem, "type", None)
    return None


def _namespaced_struct_base(struct_local: Any, owning_fn: Any) -> int | None:
    """Base slot of the ERC-7201 struct the storage pointer ``struct_local``
    aliases: the folded ``*StorageLocation`` constant the accessor's assembly
    assigns to ``$.slot``."""
    accessor = _accessor_for_pointer(struct_local, owning_fn)
    if accessor is None:
        return None
    constants = [
        v
        for v in _state_variables_read(accessor)
        if getattr(v, "is_constant", False) and str(getattr(v, "type", "")) == "bytes32"
    ]
    if len(constants) != 1:
        return None
    folded = _bytes32_constant_value(constants[0])
    if folded is None:
        return None
    try:
        return int(folded, 16)
    except ValueError:
        return None


def _accessor_for_pointer(struct_local: Any, owning_fn: Any) -> Any | None:
    """The internal accessor (``_getERC20Storage``) whose return is assigned to
    the storage pointer local."""
    dm = _defining_map(owning_fn)
    value: Any = struct_local
    for _ in range(_MAX_TRACE_DEPTH):
        defining = _defining_of(dm, value)
        if isinstance(defining, Assignment):
            value = getattr(defining, "rvalue", None)
            continue
        if isinstance(defining, (InternalCall, LibraryCall)):
            return getattr(defining, "function", None)
        return None
    return None


def _bytes32_constant_value(state_var: Any) -> str | None:
    from .predicates import _bytes32_constant_expression_value

    if str(getattr(state_var, "type", "")) != "bytes32":
        return None
    try:
        return _bytes32_constant_expression_value(getattr(state_var, "expression", None))
    except Exception:
        return None


def _struct_member_slot_offset(struct: Any, member_name: str) -> int | None:
    """Slot offset of ``member_name`` within ``struct``, walking members in
    declaration order under standard Solidity rules. Every preceding member
    must occupy exactly one full slot (mapping / 32-byte scalar / dynamic
    array-or-string head); any sub-slot scalar means packing could shift the
    target, so the derivation is abandoned."""
    offset = 0
    for elem in getattr(struct, "elems_ordered", []) or []:
        if getattr(elem, "name", None) == member_name:
            return offset
        slots = _full_slot_count(getattr(elem, "type", None))
        if slots is None:
            return None
        offset += slots
    return None


def _full_slot_count(type_obj: Any) -> int | None:
    """``1`` for a type that occupies exactly one full 32-byte slot, else
    ``None`` (packable scalar, multi-slot aggregate, or unknown)."""
    size_spec: Any = getattr(type_obj, "storage_size", None)
    try:
        size = int(size_spec[0])
    except (TypeError, ValueError, IndexError, KeyError):
        return None
    return 1 if size == 32 else None
