"""One-shot latch analysis — initializer-family gate classification.

Mirrors ``reentrancy_pause``: a tree post-pass that re-classifies latch
leaves with ``authority_role="one_shot"`` so the resolver projects a typed
one-shot side condition instead of an opaque ``business`` one. The
``initializer``/``reinitializer``/``onlyInitializing`` modifier fact was
already recognized at extraction time (``tracking._function_is_initializer``)
but routed only to the ``Initialized`` monitoring event — never onto the
function row. This pass closes that asymmetry.

Detection keys on the standard, never on function/contract names:

  * A-spine (this pass): the OZ Initializable modifier family on an entry
    point. The latch vars are the state variables the modifier reads —
    OZ v4's packed ``_initialized``/``_initializing``, or the v5 ERC-7201
    ``INITIALIZABLE_STORAGE`` constant (Slither folds the namespaced struct
    read to that constant with a ``member_path``). Leaves in the function's
    tree that read a latch var are stamped ``one_shot``.

  * The pass also attaches ``one_shot_latch`` — the on-chain location of the
    persistent version latch (storage slot/offset/size from Slither's
    storage layout, or the v5 fixed namespaced slot) — to the version-var
    leaves, so resolution can read the live value on the deployment address
    and tell a consumed one-shot (inert) from a live one (callable by
    anyone, then latches). The transient ``_initializing`` flag — recognized
    by its placeholder-bracketed write in v4, and by the standard's own
    field name where that write is invisible (the v5 struct member, written
    through an assembly-bound storage pointer) — is stamped for the badge
    but carries no latch location: its at-rest value says nothing about
    consumption.

Whether the latch is *consumed* is mutable on-chain state — deliberately
not decided here. Static only says "this is a one-shot gate" and where the
latch lives.
"""

from __future__ import annotations

import logging
from typing import Any, cast

from .predicate_types import LeafPredicate, PredicateTree
from .slither_compat import (
    SLITHER_AVAILABLE,
    Assignment,
    Constant,
    Delete,
    HighLevelCall,
    InternalCall,
    LibraryCall,
    NodeType,
    SolidityCall,
)

logger = logging.getLogger(__name__)

# The OZ Initializable modifier family — the same standard set
# ``tracking._function_is_initializer`` keys the Initialized-event tag on.
INITIALIZER_MODIFIERS = frozenset({"initializer", "reinitializer", "onlyInitializing"})

# ``expected_version``'s provenance, recorded beside the integer so no consumer
# can read it as compiler-forced. Both arms key on the closed
# ``INITIALIZER_MODIFIERS`` name set (the residual); they differ in whether a
# source literal was actually read, which is not a difference a single label can
# carry honestly.
EXPECTED_VERSION_BASIS_REINITIALIZER_LITERAL = "oz_reinitializer_argument_literal"
EXPECTED_VERSION_BASIS_INITIALIZER_CONSTANT = "oz_initializer_modifier_standard_constant"

# OZ v5 ERC-7201 InitializableStorage struct layout: the namespaced slot holds
# ``uint64 _initialized`` then ``bool _initializing``. Slither lowers the
# struct read to the slot CONSTANT as the state variable, with the member on
# ``member_path`` — so the member name (the standard's own field name, not a
# user identifier) is the only way to pick the byte range inside the slot.
# Only the persistent version member maps to a latch location.
_OZ_V5_STRUCT_MEMBERS = {
    "_initialized": {"byte_offset": 0, "size_bytes": 8, "value_type": "uint64"},
}

# The standard's transient in-flight flag — the v4 state variable and the v5
# struct member share this field name. It is true only while an initializer
# is executing and zero at rest, so its value can never witness
# consumed-vs-live: leaves reading it are stamped for the badge but carry no
# latch location. Keyed on the standard's own field name because the
# structural detection (placeholder-bracketed writes) cannot see the v5
# form — ``$._initializing = true`` writes through an assembly-bound storage
# pointer Slither reports no state-variable write for.
_TRANSIENT_FLAG_NAME = "_initializing"


def apply_one_shot_pass(contract: Any, predicate_trees: dict[str, PredicateTree]) -> None:
    """Stamp one-shot initializer latch leaves across ``predicate_trees``.

    For every entry point carrying an initializer-family modifier, leaves
    whose operands read the modifier's latch state vars are re-classified
    ``authority_role="one_shot"`` (business/None leaves only — a leaf the
    reentrancy/pause pass already claimed keeps its classification, which
    fails closed to the generic badge). Version-var leaves additionally get
    the ``one_shot_latch`` location payload.
    """
    if not SLITHER_AVAILABLE:
        raise RuntimeError("apply_one_shot_pass requires slither")

    stamped_any = False
    for fn in getattr(contract, "functions_entry_points", []) or []:
        init_modifiers = [
            m for m in (getattr(fn, "modifiers", []) or []) if getattr(m, "name", "") in INITIALIZER_MODIFIERS
        ]
        if not init_modifiers:
            continue
        full_name = getattr(fn, "full_name", None)
        tree = predicate_trees.get(full_name) if isinstance(full_name, str) else None
        if tree is None:
            continue

        latch_vars: dict[str, Any] = {}
        transient_names: set[str] = set()
        for modifier in init_modifiers:
            for var in _all_state_variables_read(modifier):
                name = getattr(var, "name", None)
                if isinstance(name, str) and name:
                    latch_vars[name] = var
            transient_names |= _placeholder_bracketed_writes(modifier)
        if not latch_vars:
            continue

        expected_version, expected_version_basis = _expected_version(fn, init_modifiers)
        if _stamp_tree(contract, tree, latch_vars, transient_names, expected_version, expected_version_basis):
            stamped_any = True

    _apply_structural_candidates(contract, predicate_trees)

    if not stamped_any:
        return

    # Re-stamp confidence so promoted leaves don't keep their previous
    # business/low value — same discipline as the reentrancy/pause pass.
    # (Candidates never change ``authority_role``, so they don't need it.)
    from .predicates import apply_confidence_to_tree

    for tree in predicate_trees.values():
        apply_confidence_to_tree(tree)


# ---------------------------------------------------------------------------
# Tree stamping
# ---------------------------------------------------------------------------


def _stamp_tree(
    contract: Any,
    tree: PredicateTree,
    latch_vars: dict[str, Any],
    transient_names: set[str],
    expected_version: int | None,
    expected_version_basis: str | None,
) -> bool:
    stamped = False
    if tree.get("op") == "LEAF":
        leaf = tree.get("leaf")
        if leaf is not None and _maybe_stamp_leaf(
            contract, leaf, latch_vars, transient_names, expected_version, expected_version_basis
        ):
            stamped = True
        return stamped
    for child in tree.get("children") or []:
        if _stamp_tree(contract, child, latch_vars, transient_names, expected_version, expected_version_basis):
            stamped = True
    return stamped


def _maybe_stamp_leaf(
    contract: Any,
    leaf: LeafPredicate,
    latch_vars: dict[str, Any],
    transient_names: set[str],
    expected_version: int | None,
    expected_version_basis: str | None,
) -> bool:
    # Already-classified non-business leaves (reentrancy/pause/authority)
    # keep their classification — fail closed to the generic badge.
    if leaf.get("authority_role") not in ("business", None):
        return False
    read_names: list[str] = [
        name
        for op in (leaf.get("operands") or [])
        if op.get("source") == "state_variable"
        and isinstance((name := op.get("state_variable_name")), str)
        and name in latch_vars
    ]
    if not read_names:
        return False

    leaf["authority_role"] = "one_shot"
    leaf["basis"] = list(leaf.get("basis", [])) + [
        f"one-shot initializer latch: {', '.join(sorted(set(read_names)))} (initializer-family modifier)"
    ]

    # Attach the latch location to version reads only: the transient
    # in-flight flag is always false at rest, so reading it can't say
    # consumed-vs-live. Walk operands rather than var names — OZ v5 surfaces
    # both struct members under the one INITIALIZABLE_STORAGE constant,
    # distinguished only by ``member_path``, and ``_latch_location`` declines
    # the transient member. The first operand yielding a location wins.
    for operand in leaf.get("operands") or []:
        if operand.get("source") != "state_variable":
            continue
        name = operand.get("state_variable_name")
        if not isinstance(name, str) or name not in latch_vars or name in transient_names:
            continue
        latch = _latch_location(
            contract,
            latch_vars[name],
            cast("dict[str, Any]", operand),
            expected_version,
            expected_version_basis,
        )
        if latch is not None:
            leaf["one_shot_latch"] = latch
            break
    return True


# ---------------------------------------------------------------------------
# Latch location
# ---------------------------------------------------------------------------


def _latch_location(
    contract: Any,
    state_var: Any,
    operand: dict[str, Any] | None,
    expected_version: int | None,
    expected_version_basis: str | None = None,
) -> dict[str, Any] | None:
    """On-chain location of the persistent latch read by ``state_var``.

    Two shapes:
      * a regular (possibly inherited) storage variable — slot/offset from
        Slither's storage layout;
      * the OZ v5 ERC-7201 pattern — the "variable" is the slot CONSTANT
        (bytes32), the member name on the operand picks the byte range of
        the standard InitializableStorage struct.
    Decisive payloads carry ``role="version"`` — the pass's positive claim
    that the location holds the persistent version member, the only state a
    consumed-vs-live verdict may be decided from (``one_shot_probe`` keys
    its selection on it). Returns None when no readable location exists
    (constant slot whose value can't be folded, immutables, layout failures)
    or when the read targets the transient in-flight flag — resolution then
    reports indeterminate rather than guessing.
    """
    if getattr(state_var, "is_constant", False):
        slot = _bytes32_constant_value(state_var)
        if slot is None:
            return None
        member = None
        if operand is not None:
            path = operand.get("member_path") or []
            member = path[0] if path else None
        if member == _TRANSIENT_FLAG_NAME:
            return None
        member_layout = _OZ_V5_STRUCT_MEMBERS.get(member or "")
        if member_layout is None:
            # A namespaced struct we don't have a standard layout for: record
            # the slot; resolution may only use the all-zero-slot fact.
            return {
                "kind": "storage",
                "variable": getattr(state_var, "name", None),
                "slot": slot,
                "byte_offset": None,
                "size_bytes": None,
                "value_type": None,
                "expected_version": expected_version,
                "expected_version_basis": expected_version_basis,
                "standard": "namespaced_slot_constant",
            }
        return {
            "kind": "storage",
            "role": "version",
            "variable": getattr(state_var, "name", None),
            "slot": slot,
            "byte_offset": member_layout["byte_offset"],
            "size_bytes": member_layout["size_bytes"],
            "value_type": member_layout["value_type"],
            "expected_version": expected_version,
            "expected_version_basis": expected_version_basis,
            "standard": "oz_v5_namespaced",
        }

    if getattr(state_var, "is_immutable", False):
        return None

    # The v4 transient flag can reach here through reads the
    # placeholder-bracket detection doesn't see (an ``onlyInitializing``-only
    # chain never writes it): same rule — badge only, no location.
    if getattr(state_var, "name", None) == _TRANSIENT_FLAG_NAME:
        return None

    layout = _storage_layout_for(contract, state_var)
    if layout is None:
        return None
    slot_index, byte_offset = layout
    try:
        size_bytes = int(state_var.type.storage_size[0])
    except Exception:
        size_bytes = None
    return {
        "kind": "storage",
        "role": "version",
        "variable": getattr(state_var, "name", None),
        "slot": "0x" + format(int(slot_index), "064x"),
        "byte_offset": int(byte_offset),
        "size_bytes": size_bytes,
        "value_type": str(getattr(state_var, "type", "")) or None,
        "expected_version": expected_version,
        "expected_version_basis": expected_version_basis,
        "standard": "storage_layout",
    }


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


def _bytes32_constant_value(state_var: Any) -> str | None:
    from .predicates import _bytes32_constant_expression_value

    if str(getattr(state_var, "type", "")) != "bytes32":
        return None
    try:
        return _bytes32_constant_expression_value(getattr(state_var, "expression", None))
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Modifier introspection
# ---------------------------------------------------------------------------


def _all_state_variables_read(modifier: Any) -> list[Any]:
    reader = getattr(modifier, "all_state_variables_read", None)
    if reader is None:
        return []
    try:
        result: Any = reader() if callable(reader) else reader
    except Exception:
        return []
    return list(result or [])


def _placeholder_bracketed_writes(modifier: Any) -> set[str]:
    """State vars written both before and after the modifier's PLACEHOLDER —
    the transient in-flight flag pattern (``_initializing = true; _;
    _initializing = false``), structurally the same bracketing the
    reentrancy analyzer keys on."""
    nodes = list(getattr(modifier, "nodes", []) or [])
    placeholder_index = None
    for index, node in enumerate(nodes):
        if getattr(node, "type", None) == getattr(NodeType, "PLACEHOLDER", -1):
            placeholder_index = index
            break
    if placeholder_index is None:
        return set()

    def writes(node_list: list[Any]) -> set[str]:
        out: set[str] = set()
        for node in node_list:
            for var in getattr(node, "state_variables_written", []) or []:
                name = getattr(var, "name", None)
                if isinstance(name, str):
                    out.add(name)
        return out

    return writes(nodes[:placeholder_index]) & writes(nodes[placeholder_index + 1 :])


def _expected_version(fn: Any, init_modifiers: list[Any]) -> tuple[int | None, str | None]:
    """``(version, basis)`` — the version the latch must reach for this gate to
    be consumed, and where that integer came from. 1 for ``initializer`` (the
    standard's own constant, not a value read from this source), the literal
    argument for ``reinitializer(n)``. ``(None, None)`` when it can't be
    determined statically (non-literal reinitializer version, or an
    ``onlyInitializing``-only helper) — never a defaulted 1."""
    names = {getattr(m, "name", "") for m in init_modifiers}
    if "reinitializer" in names:
        literal = _reinitializer_literal(fn)
        if literal is None:
            return None, None
        return literal, EXPECTED_VERSION_BASIS_REINITIALIZER_LITERAL
    if "initializer" in names:
        return 1, EXPECTED_VERSION_BASIS_INITIALIZER_CONSTANT
    return None, None


def _reinitializer_literal(fn: Any) -> int | None:
    for statement in getattr(fn, "modifiers_statements", []) or []:
        modifier = getattr(statement, "modifier", None)
        if getattr(modifier, "name", "") != "reinitializer":
            continue
        for node in getattr(statement, "nodes", []) or []:
            expression = getattr(node, "expression", None)
            for argument in getattr(expression, "arguments", []) or []:
                value = getattr(argument, "value", None)
                if isinstance(value, int):
                    return value
                if isinstance(value, str):
                    try:
                        return int(value, 0)
                    except ValueError:
                        continue
    return None


# ---------------------------------------------------------------------------
# Name-free structural latch candidates (the recall net under the A-spine).
#
# A custom one-shot the OZ modifier misses — FiatToken's ``initialized`` bool,
# a versioned ``_initializedVersion`` counter, Lido's unstructured-storage
# initialization block — is structurally: a public function whose guard reads
# non-caller-keyed persistent state that the function itself writes into the
# guard-falsifying value. Three concrete forms are detected, all stamped as
# CANDIDATES ONLY (``one_shot_candidate`` — ``authority_role`` and the badge
# are untouched): a candidate earns a badge solely through the on-chain latch
# read at resolution time, so a residual false positive costs one wasted read.
#
#   1. scalar state var:    require(!initialized) … initialized = true
#   2. getter + slot link:  require(getContractVersion() == 0) where the
#      nullary view resolves to a constant-slot read and the function writes
#      that same slot through a state-mutating assembly helper
#      (UnstructuredStorage.setStorageUint256-style).
#   3. modifier-anchored:   the guard leaf saturated in folding (Lido), but a
#      require-bearing modifier reads exactly one constant slot that the
#      function then writes — recorded on the tree root.
#
# Counters are excluded by the falsification requirement: every write the
# function makes to the latch must be a constant that permanently violates
# the guard (``deposit_count += 1`` is not a constant write; a capped
# ``v < N`` guard is only falsified by writing exactly >= N).
# ---------------------------------------------------------------------------

_SCALAR_LATCH_TYPES_PREFIXES = ("bool", "uint", "int", "address")


def _apply_structural_candidates(contract: Any, predicate_trees: dict[str, PredicateTree]) -> None:
    for fn in getattr(contract, "functions_entry_points", []) or []:
        modifier_names = {getattr(m, "name", "") for m in (getattr(fn, "modifiers", []) or [])}
        if modifier_names & INITIALIZER_MODIFIERS:
            continue  # the A-spine owns recognized-standard initializers
        full_name = getattr(fn, "full_name", None)
        tree = predicate_trees.get(full_name) if isinstance(full_name, str) else None
        if tree is None:
            continue

        const_writes: dict[str, dict[str, Any]] | None = None
        slot_writes: set[str] | None = None
        stamped_leaf = False

        def visit(node: PredicateTree) -> None:
            nonlocal const_writes, slot_writes, stamped_leaf
            if node.get("op") == "LEAF":
                leaf = node.get("leaf")
                if leaf is None or not _candidate_leaf_shape(leaf):
                    return
                if const_writes is None:
                    const_writes = _constant_state_var_writes(fn)
                payload = _scalar_candidate(contract, leaf, const_writes)
                if payload is None:
                    if slot_writes is None:
                        slot_writes = _assembly_slot_writes(fn)
                    payload = _getter_candidate(contract, leaf, slot_writes)
                if payload is not None:
                    leaf["one_shot_candidate"] = True
                    leaf["one_shot_latch"] = payload
                    leaf["basis"] = list(leaf.get("basis", [])) + [
                        f"structural one-shot latch candidate: {payload.get('variable') or payload.get('slot')}"
                    ]
                    stamped_leaf = True
                return
            for child in node.get("children") or []:
                visit(child)

        visit(tree)

        if not stamped_leaf:
            if slot_writes is None:
                slot_writes = _assembly_slot_writes(fn)
            payload = _modifier_slot_candidate(fn, slot_writes)
            if payload is not None:
                tree["one_shot_candidate_latch"] = payload  # type: ignore[typeddict-unknown-key]


def _candidate_leaf_shape(leaf: LeafPredicate) -> bool:
    if leaf.get("authority_role") not in ("business", None):
        return False
    if leaf.get("references_msg_sender"):
        return False
    if leaf.get("kind") not in ("equality", "comparison"):
        return False
    if leaf.get("set_descriptor"):
        return False
    sources = [(op or {}).get("source") for op in leaf.get("operands") or []]
    banned = {"msg_sender", "tx_origin", "signature_recovery", "parameter", "block_context"}
    return not (set(sources) & banned)


def _scalar_candidate(
    contract: Any,
    leaf: LeafPredicate,
    const_writes: dict[str, dict[str, Any]],
) -> dict[str, Any] | None:
    operands = leaf.get("operands") or []
    # Partition by position. The equality form this replaces was correct only
    # because the state-variable test is a pure function of the operand dict;
    # the invariant here is local to the partition instead.
    sv_idxs = [i for i, op in enumerate(operands) if op.get("source") == "state_variable" and not op.get("member_path")]
    excluded = set(sv_idxs)
    other = [op for i, op in enumerate(operands) if i not in excluded]
    if len(sv_idxs) != 1 or any(op.get("source") != "constant" for op in other):
        return None
    name = operands[sv_idxs[0]].get("state_variable_name")
    if not isinstance(name, str) or not name:
        return None
    writes = const_writes.get(name)
    if not writes or writes["non_constant"] or not writes["values"]:
        return None

    guard_constant = _parse_constant(other[0].get("constant_value")) if other else None
    operator = leaf.get("operator")
    if not all(_write_falsifies_guard(operator, guard_constant, value) for value in writes["values"]):
        return None
    if not _is_monotonic_ascent_latch(operator, guard_constant, writes["values"]):
        return None

    state_var = _state_variable_by_name(contract, name)
    if state_var is None or not _is_scalar_latch_type(state_var):
        return None
    if getattr(state_var, "is_constant", False) or getattr(state_var, "is_immutable", False):
        return None
    layout = _storage_layout_for(contract, state_var)
    if layout is None:
        return None
    slot_index, byte_offset = layout
    try:
        size_bytes = int(state_var.type.storage_size[0])
    except Exception:
        size_bytes = None
    return {
        "kind": "storage",
        "variable": name,
        "slot": "0x" + format(int(slot_index), "064x"),
        "byte_offset": int(byte_offset),
        "size_bytes": size_bytes,
        "value_type": str(getattr(state_var, "type", "")) or None,
        "standard": "structural_scalar_latch",
        "guard": {
            "operator": operator,
            "constant": str(guard_constant) if guard_constant is not None else None,
        },
    }


def _getter_candidate(contract: Any, leaf: LeafPredicate, slot_writes: set[str]) -> dict[str, Any] | None:
    """``require(<nullaryView>() == 0)`` where the view resolves to one
    constant-slot read and this function writes the same slot."""
    if not slot_writes:
        return None
    operands = leaf.get("operands") or []
    views = [op for op in operands if op.get("source") == "view_call"]
    other = [op for op in operands if op.get("source") != "view_call"]
    if len(views) != 1 or any(op.get("source") != "constant" for op in other):
        return None
    # ALLOW must be the unset form: == 0 (post polarity-fold) or falsy.
    operator = leaf.get("operator")
    guard_constant = _parse_constant(other[0].get("constant_value")) if other else None
    if not ((operator == "eq" and guard_constant == 0) or (operator == "falsy" and guard_constant in (None, 0))):
        return None
    view = views[0]
    signature = view.get("callee_signature")
    callee_name = view.get("callee")
    if not isinstance(signature, str) or not signature.endswith("()"):
        return None
    getter = _nullary_view_by_name(contract, callee_name)
    if getter is None:
        return None
    read_slots = _assembly_slot_reads(getter)
    if len(read_slots) != 1:
        return None
    slot = next(iter(read_slots))
    if slot not in slot_writes:
        return None
    return {
        "kind": "storage",
        "variable": callee_name,
        "slot": slot,
        "byte_offset": None,
        "size_bytes": None,
        "value_type": None,
        "standard": "unstructured_slot_latch",
        "guard": {"operator": "eq", "constant": "0"},
        "getter_selector": view.get("callee_selector"),
        "getter_signature": signature,
    }


def _modifier_slot_candidate(fn: Any, slot_writes: set[str]) -> dict[str, Any] | None:
    """A require-bearing modifier reading exactly one constant slot the
    function then writes — the guard leaf itself saturated in folding."""
    if not slot_writes:
        return None
    for modifier in getattr(fn, "modifiers", []) or []:
        if not _contains_require_or_revert(modifier):
            continue
        read_slots = _assembly_slot_reads(modifier)
        if len(read_slots) != 1:
            continue
        slot = next(iter(read_slots))
        if slot in slot_writes:
            return {
                "kind": "storage",
                "variable": getattr(modifier, "name", None),
                "slot": slot,
                "byte_offset": None,
                "size_bytes": None,
                "value_type": None,
                "standard": "unstructured_slot_latch",
                "guard": {"operator": "eq", "constant": "0"},
            }
    return None


def _is_monotonic_ascent_latch(operator: Any, guard_constant: int | None, written: set[int]) -> bool:
    """A consuming latch admits while the value sits at a floor and every
    self-write moves it strictly UP — the FiatToken ``!initialized``/
    ``_initializedVersion == k`` shape. The inverted polarity (ALLOW while
    the flag is SET, write clears it — ``unpauseContract``-style toggles)
    is re-armable by the symmetric setter and must never read as a latch."""
    if operator == "falsy":
        return all(value > 0 for value in written)
    if guard_constant is None:
        return False
    if operator == "eq":
        return all(value > guard_constant for value in written)
    if operator == "lt":
        return all(value >= guard_constant for value in written)
    if operator == "lte":
        return all(value > guard_constant for value in written)
    return False  # truthy / ne / gt / gte: descending or inverted forms


def _write_falsifies_guard(operator: Any, guard_constant: int | None, written: int) -> bool:
    """Does writing ``written`` into the latch make the ALLOW predicate
    (already polarity-folded by the static stage) false forever after?"""
    if operator == "falsy":
        return written != 0
    if operator == "truthy":
        return written == 0
    if guard_constant is None:
        return False
    if operator == "eq":
        return written != guard_constant
    if operator == "ne":
        return written == guard_constant
    if operator == "lt":
        return written >= guard_constant
    if operator == "lte":
        return written > guard_constant
    if operator == "gt":
        return written <= guard_constant
    if operator == "gte":
        return written < guard_constant
    return False


def _parse_constant(raw: Any) -> int | None:
    if isinstance(raw, bool):
        return int(raw)
    if isinstance(raw, int):
        return raw
    if isinstance(raw, str):
        text = raw.strip()
        if text.lower() in ("true", "false"):
            return int(text.lower() == "true")
        try:
            return int(text, 0)
        except ValueError:
            return None
    return None


def _is_scalar_latch_type(state_var: Any) -> bool:
    type_name = str(getattr(state_var, "type", ""))
    return type_name.startswith(_SCALAR_LATCH_TYPES_PREFIXES) and "[" not in type_name and "mapping" not in type_name


def _state_variable_by_name(contract: Any, name: str) -> Any | None:
    variables = getattr(contract, "state_variables_ordered", None) or getattr(contract, "state_variables", []) or []
    for var in variables:
        if getattr(var, "name", None) == name:
            return var
    return None


def _nullary_view_by_name(contract: Any, name: Any) -> Any | None:
    if not isinstance(name, str) or not name:
        return None
    name = name.split("(", 1)[0]  # operands may carry "getContractVersion()"
    for fn in getattr(contract, "functions", []) or []:
        if getattr(fn, "name", None) != name:
            continue
        if getattr(fn, "parameters", None):
            continue
        if getattr(fn, "view", False) or getattr(fn, "pure", False):
            return fn
    return None


# ---------------------------------------------------------------------------
# IR surveys (recursive through internal/library calls, cycle-safe)
# ---------------------------------------------------------------------------


def _walk_ir(containers: list[Any]):
    """Yield every IR operation reachable from ``containers`` (functions /
    modifiers), recursing through internal and library callees once each."""
    visited: set[int] = set()
    stack = [c for c in containers if c is not None]
    while stack:
        container = stack.pop()
        cid = id(container)
        if cid in visited:
            continue
        visited.add(cid)
        for node in getattr(container, "nodes", []) or []:
            for ir in getattr(node, "irs", []) or []:
                yield ir
                if isinstance(ir, (InternalCall, LibraryCall)):
                    callee = getattr(ir, "function", None)
                    if callee is not None and getattr(callee, "nodes", None):
                        stack.append(callee)


def _constant_state_var_writes(fn: Any) -> dict[str, dict[str, Any]]:
    """``{state_var_name: {"values": set[int], "non_constant": bool}}`` over
    every write reachable from ``fn`` (its body, callees, and modifiers)."""
    out: dict[str, dict[str, Any]] = {}

    def record(name: str, value: int | None) -> None:
        entry = out.setdefault(name, {"values": set(), "non_constant": False})
        if value is None:
            entry["non_constant"] = True
        else:
            entry["values"].add(value)

    containers = [fn] + list(getattr(fn, "modifiers", []) or [])
    for ir in _walk_ir(containers):
        lvalue = getattr(ir, "lvalue", None)
        name = _state_var_base_name(lvalue)
        if name is None:
            continue
        if isinstance(ir, Assignment):
            rvalue = getattr(ir, "rvalue", None)
            if isinstance(rvalue, Constant):
                record(name, _parse_constant(getattr(rvalue, "value", None)))
            else:
                record(name, None)
        elif isinstance(ir, Delete):
            record(name, 0)
        elif not isinstance(ir, (InternalCall, LibraryCall, HighLevelCall, SolidityCall)):
            # Any other lvalue-bearing op landing on a state var (Binary on a
            # storage ref, Unpack, …) is a non-constant write.
            record(name, None)

    return out


def _state_var_base_name(value: Any) -> str | None:
    if value is None:
        return None
    try:
        from slither.core.variables.state_variable import StateVariable
        from slither.slithir.variables import ReferenceVariable
    except Exception:  # pragma: no cover
        return None
    if isinstance(value, StateVariable):
        return getattr(value, "name", None)
    if isinstance(value, ReferenceVariable):
        points = getattr(value, "points_to_origin", None)
        if isinstance(points, StateVariable):
            return getattr(points, "name", None)
    return None


def _assembly_slot_writes(fn: Any) -> set[str]:
    """Constant storage slots written via state-mutating assembly helpers —
    a nonview callee that contains assembly and takes a bytes32-constant
    argument (the UnstructuredStorage ``setStorageUint256(POSITION, v)``
    shape)."""
    return _assembly_slot_args(
        [fn] + list(getattr(fn, "modifiers", []) or []),
        want_mutating=True,
    )


def _assembly_slot_reads(container: Any) -> set[str]:
    """Constant storage slots read via view assembly helpers reachable from
    ``container`` (``getStorageUint256(POSITION)``-shape)."""
    return _assembly_slot_args([container], want_mutating=False)


def _assembly_slot_args(containers: list[Any], *, want_mutating: bool) -> set[str]:
    slots: set[str] = set()
    for ir in _walk_ir(containers):
        if not isinstance(ir, (InternalCall, LibraryCall, HighLevelCall)):
            continue
        callee = getattr(ir, "function", None)
        if callee is None or not getattr(callee, "contains_assembly", False):
            continue
        is_view = bool(getattr(callee, "view", False) or getattr(callee, "pure", False))
        if want_mutating == is_view:
            continue
        for argument in getattr(ir, "arguments", []) or []:
            slot = _bytes32_constant_arg_value(argument)
            if slot is not None:
                slots.add(slot)
    return slots


def _bytes32_constant_arg_value(argument: Any) -> str | None:
    """The 0x-hex value of a bytes32 CONSTANT state variable passed as a call
    argument (``CONTRACT_VERSION_POSITION``), or a literal bytes32 constant."""
    try:
        from slither.core.variables.state_variable import StateVariable
    except Exception:  # pragma: no cover
        return None
    if isinstance(argument, StateVariable):
        if getattr(argument, "is_constant", False) and str(getattr(argument, "type", "")) == "bytes32":
            from .predicates import _bytes32_constant_expression_value

            try:
                return _bytes32_constant_expression_value(getattr(argument, "expression", None))
            except Exception:
                return None
        return None
    if isinstance(argument, Constant):
        value = getattr(argument, "value", None)
        if isinstance(value, int) and value > 0:
            return "0x" + format(value, "064x")
        if isinstance(value, str) and value.startswith("0x") and len(value) == 66:
            return value.lower()
    return None


def _contains_require_or_revert(container: Any) -> bool:
    for ir in _walk_ir([container]):
        if isinstance(ir, SolidityCall):
            name = getattr(getattr(ir, "function", None), "name", "") or ""
            if name.startswith("require(") or name.startswith("revert"):
                return True
    return False
