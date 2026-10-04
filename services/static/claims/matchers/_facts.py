"""Shared fact readers for the behavior matchers (registers no claims).

Per-contract derivations are memoized per ``ClaimContext`` so a ``build_claims`` pass computes them once.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any
from weakref import WeakKeyDictionary

from utils.clock_gate import SECONDS_CLOCK_KINDS, clock_kinds
from utils.scoring_status import (
    SELF_SERVICE_DISCLOSE_SIBLING,
    SELF_SERVICE_DISCLOSE_UPGRADE,
    SELF_SERVICE_STATE_PROVEN,
    W2_BASIS_CLEAR_DOMINATES_CALLS,
)

from ..context import ClaimContext, abi_selector, selector_of

# Keyed by the per-contract ClaimContext.
_PAUSE_TARGETS: WeakKeyDictionary[ClaimContext, set[tuple[str, str | None]]] = WeakKeyDictionary()
_MANDATORY_READS: WeakKeyDictionary[ClaimContext, set[tuple[str, str | None]]] = WeakKeyDictionary()
_TOTAL_SUPPLY_VARS: WeakKeyDictionary[ClaimContext, set[str]] = WeakKeyDictionary()


def _iter_leaves(tree: Any) -> Any:
    if not isinstance(tree, dict):
        return
    if tree.get("op") == "LEAF":
        leaf = tree.get("leaf")
        if isinstance(leaf, dict):
            yield leaf
        return
    for child in tree.get("children") or []:
        yield from _iter_leaves(child)


def tree_has_role(tree: Any, roles: tuple[str, ...]) -> bool:
    return any(leaf.get("authority_role") in roles for leaf in _iter_leaves(tree))


def tree_is_authority_gated(tree: Any) -> bool:
    return tree_has_role(tree, ("caller_authority", "delegated_authority"))


def tree_is_one_shot(tree: Any) -> bool:
    """An initializer latch: writes are one-time sets, never a toggle."""
    return tree_has_role(tree, ("one_shot",))


def _mandatory_operands(tree: Any) -> set[tuple[str, str | None]]:
    """State-var operands on a mandatory gate path (only ``AND`` ancestors, so the value can force a revert with no
    ``OR`` escape). Separates a real pause gate from a mode selector under a branch (``if (executorRequired)
    require(sig)``).
    """
    out: set[tuple[str, str | None]] = set()

    def walk(node: Any, mandatory: bool) -> None:
        if not isinstance(node, dict):
            return
        op = node.get("op")
        if op == "LEAF":
            if not mandatory:
                return
            leaf = node.get("leaf")
            if not isinstance(leaf, dict):
                return
            for operand in leaf.get("operands") or []:
                if not isinstance(operand, dict):
                    continue
                name = operand.get("state_variable_name")
                if not name:
                    continue
                member_path = operand.get("member_path") or []
                out.add((name, member_path[0] if member_path else None))
            return
        child_mandatory = mandatory and op != "OR"
        for child in node.get("children") or []:
            walk(child, child_mandatory)

    walk(tree, True)
    return out


def mandatory_gate_reads(ctx: ClaimContext) -> set[tuple[str, str | None]]:
    """Every ``(var, member)`` read as a mandatory revert gate in the contract (cached)."""
    cached = _MANDATORY_READS.get(ctx)
    if cached is not None:
        return cached
    reads: set[tuple[str, str | None]] = set()
    for signature in ctx.function_signatures():
        tree = ctx.predicate_tree(signature)
        if tree is not None:
            reads |= _mandatory_operands(tree)
    _MANDATORY_READS[ctx] = reads
    return reads


# Parameter destination constraints: does a mandatory revert gate reference each ABI parameter between entry and sink?
# Three states:
#
# ``constrained``: a mandatory leaf ties the parameter to something the caller doesn't control; the verdict names the
# guard. ``unconstrained_proven``: the tree exists, no mandatory leaf pins or opaquely touches the parameter, and every
# mandatory leaf's operand account is checkably complete; a leaf's silence is only evidence when its account is
# trustworthy. ``not_determined``: everything else.
#
# Completeness checks (each guards a measured over-claim): a leaf whose ``expression`` names a parameter its operands
# don't carry blocks that parameter; a non-membership leaf reading a keyed collection without its key blocks every
# parameter; a record without ``parameter_names`` can't be checked, so proves nothing. Leaf ``confidence`` grades the
# authority classification, not the operand account, so it isn't consulted.
#
# Proven OZ timelock ``execute`` and Safe ``execTransaction`` entries commit every parameter by the standard's shape
# (shared with ``exec.arbitrary`` so the witnesses agree). Safe module-exec entries don't: their gate allowlists the
# caller only.
#
# A mandatory leaf that is the revert surface of the call carrying the described effect is transparent
# (``safeTransfer(_to, bal)`` reverting constrains nothing). The join is against the facts, matching selector or bare
# callee name (declared signatures with interface params hash differently). View/pure external callees are real
# preconditions; other effectful callees stay unresolved.
#
# ``derived_from`` is flow-insensitive: a binding through it may prove ``constrained`` but never ``pins: True``, and
# absence from it proves nothing, so computed operands block ``unconstrained_proven``.

_MEMBERSHIP_SET_KINDS = frozenset({"mapping_membership", "array_contains", "external_set"})
_EXTERNAL_GATE_KINDS = frozenset({"external_call_revert", "try_catch_revert"})

# Whether a guard kind pins the parameter (only a proven pin may soften the caller-chosen reading): True confines it to
# a set the caller didn't write (allowlist, commitment, equality vs storage); False provably doesn't (denylist, ordering
# bound); None when the set semantics belong to another contract (``external_call_revert``: a blacklist and an allowlist
# look identical here, and the ones observed were blacklists).
_GUARD_PINS: dict[str, bool | None] = {
    "mapping_allowlist": True,
    "hash_commitment": True,
    "signature_witness": True,
    "equality_vs_storage": True,
    "equality_vs_caller": True,
    "denylist": False,
    "numeric_bound": False,
    "external_call_revert": None,
}

# An ``unsupported`` leaf always publishes empty operands, so its silence normally blocks the proof. Exceptions, by what
# the gate's input structurally is: ``abi.decode`` gates on call returndata (the sibling ``external_bool`` leaf carries
# the callee and parameters, as in SafeERC20), and ``tload``/``sload`` gate on a slot literal. Everything else, notably
# ``opaque_try_catch`` and unknown reasons, keeps blocking.
_NON_PARAMETRIC_UNSUPPORTED_PREFIXES = (
    "solidity_call_abi.decode()",
    "solidity_call_tload(",
    "solidity_call_sload(",
)


def _unsupported_leaf_is_parametric(leaf: dict[str, Any]) -> bool:
    reason = leaf.get("unsupported_reason")
    if not isinstance(reason, str):
        return True
    return not reason.startswith(_NON_PARAMETRIC_UNSUPPORTED_PREFIXES)


_PARAM_CONSTRAINTS: WeakKeyDictionary[ClaimContext, dict[tuple[str, str], dict[int, dict[str, Any]]]] = (
    WeakKeyDictionary()
)
_KEYED_COLLECTIONS: WeakKeyDictionary[ClaimContext, frozenset[str]] = WeakKeyDictionary()

_IDENTIFIER_RE = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*")


def _declared_param_indices(ctx: ClaimContext, function: str) -> dict[str, int] | None:
    """``{parameter_name: abi_index}`` from the record's ``parameter_names``, or ``None`` on stale artifacts (then
    nothing can be proven absent).
    """
    record = ctx.effect_record(function)
    names = record.get("parameter_names")
    if not isinstance(names, list) or not all(isinstance(name, str) for name in names):
        return None
    return {name: index for index, name in enumerate(names) if name}


def _unaccounted_param_mentions(leaf: dict[str, Any], name_indices: dict[str, int], accounted: set[int]) -> set[int]:
    """Parameter indices the leaf's expression names but its operands don't carry: the projection dropped a
    reference.

    Revert-string collisions only cost an under-claim.
    """
    expression = leaf.get("expression")
    if not isinstance(expression, str) or not expression or not name_indices:
        return set()
    out: set[int] = set()
    for token in _IDENTIFIER_RE.findall(expression):
        index = name_indices.get(token)
        if index is not None and index not in accounted:
            out.add(index)
    return out


def keyed_collection_vars(ctx: ClaimContext) -> frozenset[str]:
    """State variables declared as mappings or arrays (cached), to spot a leaf that folded an element read down to
    the bare collection.
    """
    cached = _KEYED_COLLECTIONS.get(ctx)
    if cached is not None:
        return cached
    out: set[str] = set()
    for signature in ctx.function_signatures():
        for write in state_writes(ctx, signature, body_only=False):
            var = write.get("var")
            declared = write.get("declared_type")
            if (
                isinstance(var, str)
                and isinstance(declared, str)
                and (declared.startswith("mapping(") or declared.endswith("]"))
            ):
                out.add(var)
    frozen = frozenset(out)
    _KEYED_COLLECTIONS[ctx] = frozen
    return frozen


def _reads_keyed_collection_without_key(leaf: dict[str, Any], collections: frozenset[str]) -> bool:
    """True when a non-membership leaf carries a mapping/array as a bare operand: an element read whose key (possibly
    parameter-derived) was dropped. Membership leaves and ``length`` reads account for their keys.
    """
    if not collections:
        return False
    if leaf.get("kind") == "membership" and isinstance(leaf.get("set_descriptor"), dict):
        return False
    for operand in leaf.get("operands") or []:
        if not isinstance(operand, dict) or operand.get("source") != "state_variable":
            continue
        if operand.get("state_variable_name") not in collections:
            continue
        member_path = operand.get("member_path") or []
        if member_path and member_path[-1] == "length":
            continue
        return True
    return False


def standard_destination_commitment(ctx: ClaimContext, function: str) -> dict[str, Any] | None:
    """The standard-gate verdict covering every ABI parameter of a proven standard exec entry, or ``None``.

    OZ timelock ``execute``/``executeBatch`` require ``hashOperation(...)`` scheduled and ready (a hash commitment);
    Safe ``execTransaction`` checks owners' signatures. Module-exec entries get nothing: their gate only allowlists the
    caller, so the tree walk answers.
    """
    from ._gates import SAFE_EXEC_TRANSACTION, TIMELOCK_EXECUTE_SELECTORS, is_oz_timelock_gate, is_safe_gate

    selector = ctx.canonical_selector(function)
    if selector in TIMELOCK_EXECUTE_SELECTORS and is_oz_timelock_gate(ctx):
        return {"state": "constrained", "guard": "hash_commitment", "pins": True, "binding": "standard_gate"}
    if selector == SAFE_EXEC_TRANSACTION and is_safe_gate(ctx):
        return {"state": "constrained", "guard": "signature_witness", "pins": True, "binding": "standard_gate"}
    return None


def _operand_param_indices(operand: Any) -> tuple[set[int], set[int], bool]:
    """``(direct, derived, opaque)`` parameter references of one operand.

    Every ``computed`` operand is opaque: ``derived_from`` is flow-insensitive and can omit a real origin, so it only
    ever adds positive ``derived`` bindings.
    """
    direct: set[int] = set()
    derived: set[int] = set()
    opaque = False
    if not isinstance(operand, dict):
        return direct, derived, True
    source = operand.get("source")
    if source == "parameter":
        index = operand.get("parameter_index")
        if isinstance(index, int):
            direct.add(index)
        else:
            opaque = True
    elif source == "computed":
        opaque = True
        provenance = operand.get("derived_from", None)
        if isinstance(provenance, list):
            for origin in provenance:
                if isinstance(origin, dict) and origin.get("source") == "parameter":
                    index = origin.get("parameter_index")
                    if isinstance(index, int):
                        derived.add(index)
    elif source == "top":
        opaque = True
    return direct, derived, opaque


def _leaf_param_refs(leaf: dict[str, Any]) -> tuple[set[int], set[int], bool]:
    """Parameter references of a leaf: operands, ``set_descriptor`` key sources, and ``parameter_indices``."""
    direct: set[int] = set()
    derived: set[int] = set()
    opaque = leaf.get("kind") == "unsupported" and _unsupported_leaf_is_parametric(leaf)
    operands = [o for o in (leaf.get("operands") or []) if isinstance(o, dict)]
    descriptor = leaf.get("set_descriptor")
    if isinstance(descriptor, dict):
        operands.extend(k for k in (descriptor.get("key_sources") or []) if isinstance(k, dict))
    for operand in operands:
        d, dv, op = _operand_param_indices(operand)
        direct |= d
        derived |= dv
        opaque = opaque or op
    for index in leaf.get("parameter_indices") or []:
        if isinstance(index, int):
            direct.add(index)
    return direct, derived, opaque


def _leaf_callee_selector(leaf: dict[str, Any]) -> str | None:
    selector = leaf.get("callee_selector")
    if isinstance(selector, str) and selector:
        return selector
    return selector_of(leaf.get("callee_signature"))


def _leaf_callee_name(leaf: dict[str, Any]) -> str | None:
    """Bare callee name, the fallback join when a declared signature's interface params make its hash differ from the
    sink's selector.
    """
    signature = leaf.get("callee_signature")
    if not isinstance(signature, str) or "(" not in signature:
        return None
    name = signature.split("(", 1)[0].strip()
    return name or None


def _is_external_callee_leaf(leaf: dict[str, Any]) -> bool:
    """A leaf whose truth includes another contract's answer (checked external bool, signature check, or statement
    call).
    """
    if leaf.get("kind") in ("external_bool", "signature_auth"):
        return True
    if leaf.get("gate_kind") in _EXTERNAL_GATE_KINDS:
        return True
    return bool(leaf.get("callee_signature"))


def effect_sink_identities(ctx: ClaimContext, function: str, *, mode: str) -> tuple[set[str], set[str]]:
    """``(selectors, bare callee names)`` of the calls carrying the effect a claim describes; their leaves are
    transparent.

    ``value_flow``: the moves in ``value_flows`` plus a routed flow's ``router_ops``. Transparency is per op: a
    destination guard beside the router must still block. No ``router_ops`` makes nothing extra transparent (falls to
    ``not_determined``).

    ``external_call``: only body calls whose destination is proven parameter-rooted. A guard with a fixed receiver (a
    Safe transaction guard) stays outside, so it blocks. Without a Slither subject the set is empty (under-claims).
    """
    if mode == "external_call":
        from . import _taint

        identities = _taint.proven_param_destination_call_identities(ctx, function)
        if identities is None:
            return set(), set()
        return identities
    selectors: set[str] = set()
    names: set[str] = set()
    for flow in value_flows(ctx, function):
        selector = flow.get("selector")
        if isinstance(selector, str) and selector:
            selectors.add(selector)
        for op in flow.get("router_ops") or []:
            if not isinstance(op, dict):
                continue
            op_selector = op.get("selector")
            if isinstance(op_selector, str) and op_selector:
                selectors.add(op_selector)
            op_name = op.get("callee")
            if isinstance(op_name, str) and op_name:
                names.add(op_name)
    return selectors, names


def _classify_constraining_leaf(leaf: dict[str, Any], via_derived: bool) -> str | None:
    """The guard kind a mandatory leaf pins a referenced parameter with, or ``None`` (zero-address check, compare
    against a constant).
    """
    kind = leaf.get("kind")
    operator = leaf.get("operator")
    descriptor = leaf.get("set_descriptor")
    if kind == "membership" and isinstance(descriptor, dict) and descriptor.get("kind") in _MEMBERSHIP_SET_KINDS:
        # Leaves record the allowed form: truthy membership is an allowlist, falsy a denylist (which doesn't pin).
        return "denylist" if operator in ("falsy", "ne") else "mapping_allowlist"
    if kind == "signature_auth":
        return "signature_witness"
    if _is_external_callee_leaf(leaf):
        return "external_call_revert"
    if kind in ("equality", "comparison"):
        if operator in ("ne", "falsy"):
            return None
        if via_derived:
            return "hash_commitment"
        operands = [o for o in (leaf.get("operands") or []) if isinstance(o, dict)]
        if any(o.get("source") == "state_variable" for o in operands):
            return "equality_vs_storage" if kind == "equality" else "numeric_bound"
        if any(o.get("source") in ("msg_sender", "tx_origin") for o in operands):
            return "equality_vs_caller"
        if any(o.get("source") in ("external_call", "view_call") for o in operands):
            return "numeric_bound" if kind == "comparison" else "equality_vs_storage"
        return None
    return None


def _mandatory_leaves_with_paths(tree: Any) -> list[tuple[dict[str, Any], list[int]]]:
    out: list[tuple[dict[str, Any], list[int]]] = []

    def walk(node: Any, mandatory: bool, path: list[int]) -> None:
        if not isinstance(node, dict):
            return
        op = node.get("op")
        if op == "LEAF":
            leaf = node.get("leaf")
            if mandatory and isinstance(leaf, dict):
                out.append((leaf, path))
            return
        for index, child in enumerate(node.get("children") or []):
            walk(child, mandatory and op != "OR", path + [index])

    walk(tree, True, [])
    return out


def param_constraints(ctx: ClaimContext, function: str, *, mode: str = "value_flow") -> dict[int, dict[str, Any]]:
    """Per-parameter constraint verdicts for ``function`` (memoized), ``{index: {state, guard, binding,
    leaf_path}}``.

    Index ``-1`` is the function-wide default; use :func:`param_constraint`, which folds it in.
    """
    memo = _PARAM_CONSTRAINTS.setdefault(ctx, {})
    cached = memo.get((function, mode))
    if cached is not None:
        return cached

    verdicts: dict[int, dict[str, Any]] = {}

    standard = standard_destination_commitment(ctx, function)
    if standard is not None:
        # The standard commits every parameter; the tree walk could only be weaker.
        verdicts[-1] = standard
        memo[(function, mode)] = verdicts
        return verdicts

    tree = ctx.predicate_tree(function)
    if tree is None:
        # No tree: nothing is settled. A missing tree is not proof that no gate exists.
        verdicts[-1] = {"state": "not_determined"}
        memo[(function, mode)] = verdicts
        return verdicts

    effect_selectors, effect_names = effect_sink_identities(ctx, function, mode=mode)
    name_indices = _declared_param_indices(ctx, function)
    collections = keyed_collection_vars(ctx)

    blocked: set[int] = set()
    # Without ``parameter_names`` no leaf's account is checkable: positives still mint, silence proves nothing.
    blocked_all = name_indices is None
    for leaf, path in _mandatory_leaves_with_paths(tree):
        direct, derived, opaque = _leaf_param_refs(leaf)
        mentioned = _unaccounted_param_mentions(leaf, name_indices or {}, direct | derived)
        keyed_read = _reads_keyed_collection_without_key(leaf, collections)
        if _is_external_callee_leaf(leaf):
            mutability = leaf.get("callee_state_mutability")
            if mutability not in ("view", "pure"):
                selector = _leaf_callee_selector(leaf)
                name = _leaf_callee_name(leaf)
                carries_effect = (selector is not None and selector in effect_selectors) or (
                    name is not None and name in effect_names
                )
                if carries_effect:
                    # The described effect's own revert surface: transparent.
                    continue
                # An effectful callee not proven to be the described call: unevaluable, whether stamped ``nonview`` or
                # unstamped.
                blocked |= direct | derived | mentioned
                if opaque or keyed_read:
                    blocked_all = True
                continue
            # View/pure callees are genuine preconditions and fall through to classification. Parameters named without
            # an operand, and dropped collection keys, block.
        blocked |= mentioned
        if opaque or keyed_read:
            # Can reference any parameter silently: blocks the unconstrained proof for all.
            blocked_all = True
        for index in sorted(direct | derived):
            via_derived = index in derived and index not in direct
            guard = _classify_constraining_leaf(leaf, via_derived=via_derived)
            if guard is None:
                continue
            incumbent = verdicts.get(index)
            if incumbent is not None and incumbent.get("guard") != "denylist":
                continue
            binding = "derived_from" if via_derived else "operand"
            verdict: dict[str, Any] = {
                "state": "constrained",
                "guard": guard,
                # Unmapped guard kinds are None, not False. A ``derived_from`` binding caps ``pins`` at None: which
                # parameter the guard confines isn't proven.
                "pins": None if binding == "derived_from" else _GUARD_PINS.get(guard),
                "binding": binding,
                "leaf_path": list(path),
            }
            verdicts[index] = verdict

    for index in sorted(blocked):
        verdicts.setdefault(index, {"state": "not_determined"})
    if blocked_all:
        verdicts[-1] = {"state": "not_determined"}
    memo[(function, mode)] = verdicts
    return verdicts


def param_constraint(
    ctx: ClaimContext, function: str, index: int | None, *, mode: str = "value_flow"
) -> dict[str, Any]:
    """Three-state verdict for one parameter index; ``None`` index is ``not_determined``, unknown indices inherit the
    function-wide default.
    """
    if index is None or not isinstance(index, int):
        return {"state": "not_determined"}
    verdicts = param_constraints(ctx, function, mode=mode)
    verdict = verdicts.get(index)
    if verdict is not None:
        return dict(verdict)
    default = verdicts.get(-1)
    if default is not None:
        return dict(default)
    return {"state": "unconstrained_proven"}


# Self-service payout: the amount is read from a storage cell the caller is proven to own (W1) and that cell is cleared
# before any external call, or a verified reentrancy guard covers it (W2). The amount side (effects ``amount_record_*``)
# and guard side (predicates ``element_*``) both name the base by ``StateVariable.canonical_name``, so the join refuses
# on disagreement. W1 is never ``unconstrained_proven``: not owning a cell is an absence proof.

_W1_KEYED_BY_CALLER = "keyed_by_caller"
_W1_OWNER_GUARDED_RECORD = "owner_guarded_record"

_W1_AMOUNT_ROOT_NOT_CLASSIFIABLE = "amount_root_not_classifiable"
_W1_MULTIPLE_RECORD_DECLARATIONS = "multiple_record_declarations"
_W1_RECORD_MISMATCH = "record_mismatch"
_W1_KEY_INDEX_DISAGREEMENT = "key_index_disagreement"
_W1_GUARD_NOT_MANDATORY = "guard_not_mandatory"

_W2_VERIFIED_GUARD = "verified_guard"

_W2_GUARD_FUNCTION_NOT_ANALYZED = "function_not_analyzed"

# The closed vocabulary the fact publishes: W1 reasons, ordering and guard refusals, and the two positive states.
SELF_SERVICE_REFUSAL_REASONS = frozenset(
    {
        _W1_AMOUNT_ROOT_NOT_CLASSIFIABLE,
        _W1_MULTIPLE_RECORD_DECLARATIONS,
        _W1_RECORD_MISMATCH,
        _W1_KEY_INDEX_DISAGREEMENT,
        _W1_GUARD_NOT_MANDATORY,
        "clearing_write_does_not_dominate_calls",
        "no_clearing_write",
        "assembly_state_access",
        "cross_unit_ordering_unproven",
        "loop_nesting_mismatch",
        "call_enumeration_incomplete",
        "record_not_resolvable",
        "guard_modifier_not_applied",
        "no_verified_guard_modifier",
        "ambiguous_function_declaration",
        _W2_GUARD_FUNCTION_NOT_ANALYZED,
        # Burn variant, registered ahead of any producer.
        "amount_is_external_conversion_of_burn",
    }
)


_VERIFIED_GUARD_VERDICTS: WeakKeyDictionary[ClaimContext, dict[str, Any]] = WeakKeyDictionary()


def _verified_guard_verdicts(ctx: ClaimContext) -> dict[str, Any]:
    """Verified-guard verdicts per function (memoized).

    Without a Slither contract the map is empty, so lookups refuse with ``function_not_analyzed``.
    """
    cached = _VERIFIED_GUARD_VERDICTS.get(ctx)
    if cached is not None:
        return cached
    verdicts: dict[str, Any] = {}
    if ctx.contract is not None:
        from ...contract_analysis_pipeline.reentrancy_pause import verified_guard_verdicts

        try:
            verdicts = verified_guard_verdicts(ctx.contract)
        except Exception:  # pragma: no cover - a malformed contract view refuses closed
            verdicts = {}
    _VERIFIED_GUARD_VERDICTS[ctx] = verdicts
    return verdicts


def _owner_guarded_record_constraint(
    ctx: ClaimContext, function: str, flow: dict[str, Any], record: str
) -> dict[str, Any]:
    """W1 via an ownership guard: a mandatory ``caller_authority`` leaf reading the same record against
    ``msg.sender``.

    A guard names one key level, so it only vouches for a single-level record whose amount-side index is present and
    equal.
    """
    key_indexes = flow.get("amount_record_key_param_indexes")
    single_index = (
        key_indexes[0]
        if isinstance(key_indexes, list) and len(key_indexes) == 1 and isinstance(key_indexes[0], int)
        else None
    )
    tree = ctx.predicate_tree(function)
    saw_base_mismatch = False
    saw_key_mismatch = False
    if tree is not None:
        for leaf, _path in _mandatory_leaves_with_paths(tree):
            if leaf.get("authority_role") != "caller_authority":
                continue
            operands = [o for o in (leaf.get("operands") or []) if isinstance(o, dict)]
            if not any(o.get("source") == "msg_sender" for o in operands):
                continue
            for op in operands:
                if "element_base_variable" not in op:
                    continue
                # Both sides use canonical names; a bare-name match would silently fail.
                if op.get("element_base_variable") != record:
                    saw_base_mismatch = True
                    continue
                idx = op.get("element_key_param_index")
                if single_index is not None and isinstance(idx, int) and idx == single_index:
                    return {"state": "constrained", "basis": _W1_OWNER_GUARDED_RECORD, "record": record}
                # Same base, different cell (or no single amount slot to align to).
                saw_key_mismatch = True
    if saw_key_mismatch:
        reason = _W1_KEY_INDEX_DISAGREEMENT
    elif saw_base_mismatch:
        reason = _W1_RECORD_MISMATCH
    else:
        reason = _W1_GUARD_NOT_MANDATORY
    return {"state": "not_determined", "reason": reason}


def amount_record_constraint(ctx: ClaimContext, function: str, flow: dict[str, Any]) -> dict[str, Any]:
    """W1: is the flow's amount read from a record the caller is proven to own? ``constrained`` carries the basis and
    record; anything less is ``not_determined`` with the reason.
    """
    record = flow.get("amount_record_variable")
    if not isinstance(record, str) or not record:
        variables = flow.get("amount_record_variables")
        reason = (
            _W1_MULTIPLE_RECORD_DECLARATIONS
            if isinstance(variables, list) and variables
            else _W1_AMOUNT_ROOT_NOT_CLASSIFIABLE
        )
        return {"state": "not_determined", "reason": reason}

    key_kinds = flow.get("amount_record_key_kinds")
    # ``keyed_by_caller``: a key level of the cell is ``msg_sender`` (an earned origin, published only when every site
    # agreed), so the caller can only reach cells under their own address.
    if isinstance(key_kinds, list) and "msg_sender" in key_kinds:
        return {"state": "constrained", "basis": _W1_KEYED_BY_CALLER, "record": record}

    return _owner_guarded_record_constraint(ctx, function, flow, record)


def self_service_payout(ctx: ClaimContext, function: str, flow: dict[str, Any]) -> dict[str, Any]:
    """W1 and W2, three-state, proven only on the full conjunction; refusals name the failed conjunct.

    W2 is either the ordering proof or a verified guard, and the basis says which. When both refuse, the ordering reason
    wins (it explains why the code order is unsafe).
    """
    w1 = amount_record_constraint(ctx, function, flow)
    if w1.get("state") != "constrained":
        return {"state": "not_determined", "reason": w1.get("reason", _W1_AMOUNT_ROOT_NOT_CLASSIFIABLE)}

    ordering = flow.get("record_ordering")
    ordering = ordering if isinstance(ordering, dict) else {}
    guard = _verified_guard_verdicts(ctx).get(function) or {
        "state": "not_determined",
        "reason": _W2_GUARD_FUNCTION_NOT_ANALYZED,
    }

    if ordering.get("state") == "proven_ordering":
        w2_basis = W2_BASIS_CLEAR_DOMINATES_CALLS
        disclosures = [str(d) for d in (ordering.get("disclosures") or [])]
    elif guard.get("state") == "proven":
        w2_basis = _W2_VERIFIED_GUARD
        disclosures = []
    else:
        reason = ordering.get("reason") if ordering.get("state") == "not_determined" else None
        if not reason:
            reason = guard.get("reason") or _W2_GUARD_FUNCTION_NOT_ANALYZED
        return {"state": "not_determined", "reason": reason}

    return {
        "state": SELF_SERVICE_STATE_PROVEN,
        "w1_basis": w1["basis"],
        "w2_basis": w2_basis,
        "record": w1["record"],
        # Both disclosures ride every proof; the loop residual only a per-iteration ordering proof.
        "disclosures": [SELF_SERVICE_DISCLOSE_UPGRADE, SELF_SERVICE_DISCLOSE_SIBLING, *disclosures],
    }


def state_writes(ctx: ClaimContext, function: str, *, body_only: bool = True) -> list[dict[str, Any]]:
    record = ctx.effect_record(function)
    writes = record.get("state_writes")
    if not isinstance(writes, list):
        return []
    out = [w for w in writes if isinstance(w, dict)]
    if body_only:
        out = [w for w in out if w.get("origin") != "guard"]
    return out


def bool_write_targets(ctx: ClaimContext, function: str) -> set[tuple[str, str | None]]:
    """``(var, member)`` pairs this function writes as a latch flag: plain ``bool`` variables, and ERC-7201
    namespaced flags, recorded as writes to the ``bytes32`` slot pseudo-variable with no member path (a bool-only
    filter missed every OZ-v5 pause). A pseudo-slot only becomes a pause target if a mandatory gate reads the same
    slot.
    """
    out: set[tuple[str, str | None]] = set()
    for write in state_writes(ctx, function):
        declared = write.get("declared_type")
        namespaced = write.get("hygiene_class") == "storage_location_pseudo"
        if declared != "bool" and not namespaced:
            continue
        member_path = write.get("member_path") or []
        out.add((write["var"], member_path[0] if member_path else None))
    return out


def namespaced_write_vars(ctx: ClaimContext, function: str) -> set[str]:
    """Namespaced slot pseudo-variables this function writes.

    A slot aggregates a whole struct (an owner change writes the slot the owner gate reads), so callers demand stronger
    evidence for these.
    """
    return {
        str(write["var"])
        for write in state_writes(ctx, function)
        if write.get("hygiene_class") == "storage_location_pseudo" and write.get("var")
    }


def value_flows(ctx: ClaimContext, function: str, *, body_only: bool = True) -> list[dict[str, Any]]:
    record = ctx.effect_record(function)
    flows = record.get("value_flows")
    if not isinstance(flows, list):
        return []
    out = [f for f in flows if isinstance(f, dict)]
    if body_only:
        out = [f for f in out if f.get("origin") != "guard"]
    return out


def body_sinks(ctx: ClaimContext, function: str) -> list[dict[str, Any]]:
    return [s for s in ctx.sinks(function) if s.get("origin") != "guard"]


_ADDRESS_ELEMENTARY = frozenset({"address", "address payable"})


def is_scalar_pointer(variable: Any) -> bool:
    """True when the variable holds a callable 20-byte pointer (``address`` or a contract/interface type).

    Decided on the resolved type so a struct or enum can't pass: this feeds ``callee_pointer.rotate``, which grants
    admin capability.
    """
    try:
        from slither.core.declarations.contract import Contract
        from slither.core.solidity_types.elementary_type import ElementaryType
        from slither.core.solidity_types.user_defined_type import UserDefinedType
    except Exception:  # pragma: no cover - import edge
        return False
    var_type = getattr(variable, "type", None)
    if isinstance(var_type, ElementaryType):
        return var_type.name in _ADDRESS_ELEMENTARY
    if isinstance(var_type, UserDefinedType):
        return isinstance(var_type.type, Contract)
    return False


def is_erc20(ctx: ClaimContext) -> bool:
    ercs = getattr(ctx.contract, "ercs", None)
    if not callable(ercs):
        return False
    try:
        values: Any = ercs()
        return "ERC20" in {str(value) for value in values}
    except Exception:
        return False


def written_state_variables(function: Any) -> list[Any]:
    getter = getattr(function, "all_state_variables_written", None)
    if not callable(getter):
        return []
    try:
        result: Any = getter()
        return list(result)
    except Exception:
        return []


def contract_function(ctx: ClaimContext, signature: str) -> Any | None:
    """The Slither function for an effects full-name, preferring the implemented body over an inherited 0-node
    interface re-declaration (the effects builder's tie-break).
    """
    best = None
    for fn in getattr(ctx.contract, "functions", []) or []:
        full = getattr(fn, "full_name", None) or getattr(fn, "name", None)
        if full != signature:
            continue
        if best is None or _fn_prefers(fn, best):
            best = fn
    return best


def _fn_prefers(new_fn: Any, old_fn: Any) -> bool:
    new_impl = bool(getattr(new_fn, "is_implemented", False)) and bool(getattr(new_fn, "nodes", None))
    old_impl = bool(getattr(old_fn, "is_implemented", False)) and bool(getattr(old_fn, "nodes", None))
    if new_impl != old_impl:
        return new_impl
    new_shadow = bool(getattr(new_fn, "is_shadowed", False))
    old_shadow = bool(getattr(old_fn, "is_shadowed", False))
    if new_shadow != old_shadow:
        return not new_shadow
    return len(getattr(new_fn, "nodes", []) or []) > len(getattr(old_fn, "nodes", []) or [])


def contract_functions(ctx: ClaimContext, signature: str) -> list[Any]:
    """Every function object with this full-name (override and shadowed base)."""
    return [
        fn
        for fn in getattr(ctx.contract, "functions", []) or []
        if (getattr(fn, "full_name", None) or getattr(fn, "name", None)) == signature
    ]


def pause_targets(ctx: ClaimContext) -> set[tuple[str, str | None]]:
    """``(var, member)`` bool flags written in some function body and read as a mandatory revert gate by another.

    Member-path facts recover struct-member and inherited-private pauses; the mandatory structure excludes branch-mode
    selectors.
    """
    cached = _PAUSE_TARGETS.get(ctx)
    if cached is not None:
        return cached
    gate_reads = mandatory_gate_reads(ctx)
    all_bool_writes: set[tuple[str, str | None]] = set()
    for signature in ctx.function_signatures():
        all_bool_writes |= bool_write_targets(ctx, signature)
    targets = {pair for pair in all_bool_writes if _pair_is_gate_read(pair, gate_reads)}
    _PAUSE_TARGETS[ctx] = targets
    return targets


def _pair_is_gate_read(pair: tuple[str, str | None], gate_reads: set[tuple[str, str | None]]) -> bool:
    var, member = pair
    if pair in gate_reads:
        return True
    if member is not None and (var, None) in gate_reads:
        return True
    # Namespaced case: the write is on the slot with no member while the guard read carries one (``["paused"]``), so a
    # memberless write matches any read of the variable.
    return member is None and any(read_var == var for read_var, _read_member in gate_reads)


def function_pause_targets(ctx: ClaimContext, function: str) -> set[tuple[str, str | None]]:
    return bool_write_targets(ctx, function) & pause_targets(ctx)


def toggle_polarity(function: Any, var: str, member: str | None, *, alias_members: frozenset[str] = frozenset()) -> str:
    """``"set"``, ``"unset"``, or ``"both"`` (parameter- or branch-dependent).

    Follows internal callees (OZ ``_pause()``).

    ``alias_members`` handles ERC-7201 latches assigned through a local storage pointer (``$.paused = true``), which
    never name ``var``; without it every namespaced pauser would claim both directions.
    """
    polarities: set[str] = set()
    visited: set[int] = set()

    def walk(unit: Any) -> None:
        if id(unit) in visited:
            return
        visited.add(id(unit))
        for node in getattr(unit, "nodes", []) or []:
            ref_pair: dict[int, tuple[str, str]] = {}
            irs = list(getattr(node, "irs", []) or [])
            for ir in irs:
                if type(ir).__name__ != "Member":
                    continue
                base = getattr(getattr(ir, "variable_left", None), "name", None)
                member_name = getattr(getattr(ir, "variable_right", None), "name", None)
                lvalue = getattr(ir, "lvalue", None)
                if base is not None and lvalue is not None:
                    ref_pair[id(lvalue)] = (str(base), str(member_name))
            for ir in irs:
                if type(ir).__name__ != "Assignment":
                    continue
                lvalue = getattr(ir, "lvalue", None)
                if member is None:
                    named = _base_name(getattr(lvalue, "name", None)) == var
                    # A member matched by name alone must be a bool: 0 written to a uint member isn't ``false``.
                    aliased = (
                        bool(alias_members)
                        and (ref_pair.get(id(lvalue)) or ("", ""))[1] in alias_members
                        and str(getattr(lvalue, "type", "")) == "bool"
                    )
                    if not (named or aliased):
                        continue
                elif lvalue is None or ref_pair.get(id(lvalue)) != (var, member):
                    continue
                polarity = _constant_bool_polarity(getattr(ir, "rvalue", None))
                if polarity:
                    polarities.add(polarity)
            for ir in irs:
                if type(ir).__name__ in ("InternalCall", "LibraryCall"):
                    callee = getattr(ir, "function", None)
                    if callee is not None and getattr(callee, "nodes", None):
                        walk(callee)

    walk(function)
    if polarities == {"set"}:
        return "set"
    if polarities == {"unset"}:
        return "unset"
    return "both"


def _base_name(name: Any) -> str | None:
    if not isinstance(name, str):
        return None
    parts = name.rsplit("_", 1)
    if len(parts) == 2 and parts[1].isdigit():
        return parts[0]
    return name


def _constant_bool_polarity(rvalue: Any) -> str | None:
    text = getattr(rvalue, "value", None)
    if text is None:
        text = getattr(rvalue, "name", None)
    text = str(text if text is not None else rvalue or "").strip().lower()
    if text in ("true", "1"):
        return "set"
    if text in ("false", "0"):
        return "unset"
    return None


# Timestamp pause latches (``pausedUntil``): a uint the guard holds against the clock instead of a bool flag. A gate
# ``latch < block.timestamp`` blocks while the latch is ahead of the clock, so arming it to ``block.timestamp + d``
# freezes every entry point that gate covers and writing 0 lifts the freeze.

_Location = tuple[str, str | None]

_TIMESTAMP_LATCHES: WeakKeyDictionary[ClaimContext, frozenset[_Location]] = WeakKeyDictionary()
_STORAGE_ACCESS: WeakKeyDictionary[ClaimContext, dict[tuple[str, bool], _StorageAccess]] = WeakKeyDictionary()

_UINT_TYPE = re.compile(r"uint\d*")
_CLOCK_VARIABLES = frozenset({"block.timestamp", "now"})

_LATCH_WRITE_CLOCK_SUM = "clock_sum"
_LATCH_WRITE_CLEARED = "cleared"
_LATCH_WRITE_OTHER = "other"

# A member reached through a storage pointer whose slot isn't proven.
_UNRESOLVED_BASE = "?"

# The leaf records the condition that lets the call through: with the latch on the small side it blocks until the clock
# passes the latch, on the large side it is open only until then.
_LATCH_BELOW_CLOCK_OPERATORS = {0: frozenset({"lt", "lte"}), 1: frozenset({"gt", "gte"})}
_LATCH_ABOVE_CLOCK_OPERATORS = {0: frozenset({"gt", "gte"}), 1: frozenset({"lt", "lte"})}


def _clock_compared_latch(leaf: dict[str, Any], operators_by_slot: dict[int, frozenset[str]]) -> _Location | None:
    """The ``(var, member)`` a leaf compares directly against the seconds clock under ``operators_by_slot``, or
    ``None``.

    An absorbed additive group (``start + CLIFF <= block.timestamp``) is refused: the recorder doesn't keep the sign, so
    the direction against the latch isn't proven.
    """
    if leaf.get("kind") != "comparison" or leaf.get("absorbed_operands"):
        return None
    operands = [op for op in leaf.get("operands") or [] if isinstance(op, dict)]
    if len(operands) != 2:
        return None
    operator = leaf.get("operator")
    for latch_slot, operators in operators_by_slot.items():
        if operator not in operators:
            continue
        latch, clock = operands[latch_slot], operands[1 - latch_slot]
        clocks = clock_kinds([clock])
        if not clocks or not clocks <= SECONDS_CLOCK_KINDS:
            continue
        name = latch.get("state_variable_name")
        member_path = latch.get("member_path") or []
        if latch.get("source") != "state_variable" or not isinstance(name, str) or len(member_path) > 1:
            continue
        return name, (str(member_path[0]) if member_path else None)
    return None


def _demands_latch_armed(leaf: dict[str, Any], pair: _Location) -> bool:
    """True when the leaf only lets the call through once the latch is non-zero: a schedule that must be set before
    its action runs, not a freeze that is open at rest.
    """
    operands = [op for op in leaf.get("operands") or [] if isinstance(op, dict)]
    slots = [
        index
        for index, op in enumerate(operands)
        if op.get("source") == "state_variable"
        and (op.get("state_variable_name"), (op.get("member_path") or [None])[0]) == pair
    ]
    if not slots:
        return False
    operator = leaf.get("operator")
    if operator == "truthy" and len(operands) == 1:
        return True
    if len(operands) != 2:
        return False
    slot = slots[0]
    other = operands[1 - slot]
    if other.get("source") != "constant" or str(other.get("constant_value")) != "0":
        return False
    return operator == "ne" or operator == ("gt" if slot == 0 else "lt")


def _is_uint_latch_slot(value: Any) -> bool:
    return _UINT_TYPE.fullmatch(str(getattr(value, "type", "") or "")) is not None


def _latch_value_classifier(unit: Any) -> Callable[[Any], frozenset[str]]:
    """Classify the values a latch write can take in one function body.

    ``clock`` is ``block.timestamp``, ``clock_sum`` an addition with a clock summand, ``zero`` the constant 0; anything
    else is ``other``. A local assigned on several paths unions its classes, so a sum only counts when every value of
    the clock summand is a clock.
    """
    from slither.core.declarations.solidity_variables import SolidityVariable
    from slither.slithir.operations import Assignment, Binary, TypeConversion
    from slither.slithir.variables import Constant

    classes: dict[int, frozenset[str]] = {}

    def of(value: Any) -> frozenset[str]:
        if isinstance(value, SolidityVariable):
            return frozenset({"clock"}) if value.name in _CLOCK_VARIABLES else frozenset({_LATCH_WRITE_OTHER})
        if isinstance(value, Constant):
            return frozenset({"zero"}) if getattr(value, "value", None) == 0 else frozenset({_LATCH_WRITE_OTHER})
        return classes.get(id(value), frozenset({_LATCH_WRITE_OTHER}))

    irs = [ir for node in getattr(unit, "nodes", []) or [] for ir in getattr(node, "irs", []) or []]
    # Each pass only widens a set, and assignment chains are a few links deep.
    for _ in range(8):
        changed = False
        for ir in irs:
            lvalue = getattr(ir, "lvalue", None)
            if lvalue is None:
                continue
            if isinstance(ir, Assignment):
                value = of(ir.rvalue)
            elif isinstance(ir, TypeConversion):
                value = of(ir.variable)
            elif isinstance(ir, Binary):
                value = _sum_class(ir, of)
            else:
                value = frozenset({_LATCH_WRITE_OTHER})
            merged = classes.get(id(lvalue), frozenset()) | value
            if merged != classes.get(id(lvalue)):
                classes[id(lvalue)] = merged
                changed = True
        if not changed:
            break
    return of


def _sum_class(ir: Any, of: Callable[[Any], frozenset[str]]) -> frozenset[str]:
    from slither.slithir.operations import BinaryType

    if ir.type == BinaryType.ADDITION and any(
        of(summand) <= {"clock", _LATCH_WRITE_CLOCK_SUM} for summand in (ir.variable_left, ir.variable_right)
    ):
        return frozenset({_LATCH_WRITE_CLOCK_SUM})
    return frozenset({_LATCH_WRITE_OTHER})


def _slot_of_getter(callee: Any) -> str | None:
    """The slot constant a storage-pointer getter binds (``assembly { $.slot := SLOT }``), when it binds exactly one."""
    from slither.core.variables.state_variable import StateVariable
    from slither.slithir.operations import Assignment

    slots = {
        ir.rvalue.name
        for node in getattr(callee, "nodes", []) or []
        for ir in getattr(node, "irs", []) or []
        if isinstance(ir, Assignment)
        and getattr(ir.lvalue, "is_storage", False)
        and isinstance(ir.rvalue, StateVariable)
        and ir.rvalue.is_constant
    }
    return next(iter(slots)) if len(slots) == 1 else None


class _StorageAccess:
    """Storage locations one entry point touches, following internal callees.

    A location is ``(state variable, struct member)``. An ERC-7201 member is keyed by the slot constant its pointer is
    proven to bind, which is how predicate leaves name it; a member reached through an unproven pointer is keyed by
    :data:`_UNRESOLVED_BASE`. Element writes (``map[k] = v``) are recorded against the collection, never as a write of
    the scalar.
    """

    def __init__(self) -> None:
        self.latch_writes: dict[_Location, set[str]] = {}
        self.writes: set[_Location] = set()
        self.refs: set[_Location] = set()


def _storage_access(ctx: ClaimContext, signature: str, *, modifiers: bool) -> _StorageAccess:
    memo = _STORAGE_ACCESS.setdefault(ctx, {})
    cached = memo.get((signature, modifiers))
    if cached is None:
        cached = memo[(signature, modifiers)] = _collect_storage_access(ctx, signature, modifiers=modifiers)
    return cached


def _collect_storage_access(ctx: ClaimContext, signature: str, *, modifiers: bool) -> _StorageAccess:
    from slither.core.variables.state_variable import StateVariable
    from slither.slithir.operations import Assignment, Binary, Delete, Index, Member

    access = _StorageAccess()
    fn = contract_function(ctx, signature)
    if fn is None:
        return access
    visited: set[int] = set()

    def state_location(value: Any) -> _Location | None:
        if isinstance(value, StateVariable) and not value.is_constant and isinstance(value.name, str):
            return value.name, None
        return None

    def walk(unit: Any) -> None:
        if id(unit) in visited:
            return
        visited.add(id(unit))
        of = _latch_value_classifier(unit)
        pointers: dict[int, str] = {}
        refs: dict[int, tuple[_Location, bool]] = {}

        def located(value: Any) -> tuple[_Location, bool] | None:
            direct = state_location(value)
            return (direct, False) if direct is not None else refs.get(id(value))

        for node in getattr(unit, "nodes", []) or []:
            for ir in getattr(node, "irs", []) or []:
                lvalue = getattr(ir, "lvalue", None)
                if isinstance(ir, Member):
                    field = str(getattr(ir.variable_right, "name", None))
                    base = ir.variable_left
                    if id(base) in pointers:
                        refs[id(lvalue)] = ((pointers[id(base)], field), False)
                    elif (outer := located(base)) is not None:
                        (var, member), indexed = outer
                        refs[id(lvalue)] = ((var, member if member is not None else field), indexed)
                    else:
                        refs[id(lvalue)] = ((_UNRESOLVED_BASE, field), False)
                    access.refs.add(refs[id(lvalue)][0])
                    continue
                if isinstance(ir, Index):
                    outer = located(ir.variable_left)
                    if outer is not None:
                        refs[id(lvalue)] = (outer[0], True)
                        access.refs.add(outer[0])
                    continue
                if type(ir).__name__ == "InternalCall" and lvalue is not None:
                    callee = getattr(ir, "function", None)
                    slot = _slot_of_getter(callee) if callee is not None else None
                    if slot is not None:
                        pointers[id(lvalue)] = slot
                if isinstance(ir, Assignment) and getattr(lvalue, "is_storage", False):
                    rvalue = ir.rvalue
                    if isinstance(rvalue, StateVariable) and rvalue.is_constant and isinstance(rvalue.name, str):
                        pointers[id(lvalue)] = rvalue.name
                    elif id(rvalue) in pointers:
                        pointers[id(lvalue)] = pointers[id(rvalue)]
                for read in getattr(ir, "read", []) or []:
                    if (location := state_location(read)) is not None:
                        access.refs.add(location)
                target = ir.variable if isinstance(ir, Delete) else lvalue
                written = located(target) if target is not None else None
                if written is None:
                    continue
                location, indexed = written
                access.writes.add(location)
                access.refs.add(location)
                if indexed or location[0] == _UNRESOLVED_BASE or not _is_uint_latch_slot(target):
                    continue
                if isinstance(ir, Delete):
                    value = frozenset({"zero"})
                elif isinstance(ir, Assignment):
                    value = of(ir.rvalue)
                elif isinstance(ir, Binary):
                    value = _sum_class(ir, of)
                else:
                    value = frozenset({_LATCH_WRITE_OTHER})
                if value == {"zero"}:
                    kind = _LATCH_WRITE_CLEARED
                elif value == {_LATCH_WRITE_CLOCK_SUM}:
                    kind = _LATCH_WRITE_CLOCK_SUM
                else:
                    kind = _LATCH_WRITE_OTHER
                access.latch_writes.setdefault(location, set()).add(kind)
            for ir in getattr(node, "irs", []) or []:
                if type(ir).__name__ not in ("InternalCall", "LibraryCall"):
                    continue
                if not modifiers and _is_modifier_call(ir):
                    continue
                callee = getattr(ir, "function", None)
                if callee is not None and getattr(callee, "nodes", None):
                    walk(callee)

    walk(fn)
    return access


def _overlaps(a: _Location, b: _Location) -> bool:
    """Whether two locations may name the same storage; an unresolved base or a whole-variable access errs to yes."""
    (var_a, member_a), (var_b, member_b) = a, b
    if member_a is not None and member_b is not None and member_a != member_b:
        return False
    if var_a == var_b:
        return True
    return member_a is not None and member_a == member_b and _UNRESOLVED_BASE in (var_a, var_b)


def latch_writes(ctx: ClaimContext, signature: str, pair: _Location) -> frozenset[str]:
    """How ``signature`` (with its modifiers and internal callees) writes the uint latch ``pair``: ``clock_sum``,
    ``cleared`` (0 or ``delete``) or ``other``. Empty when it never writes it.
    """
    return frozenset(_storage_access(ctx, signature, modifiers=True).latch_writes.get(pair, ()))


def _may_write(ctx: ClaimContext, signature: str, pair: _Location) -> bool:
    return any(_overlaps(pair, written) for written in _storage_access(ctx, signature, modifiers=True).writes)


def _authority_writer(ctx: ClaimContext, signature: str) -> bool:
    tree = ctx.predicate_tree(signature)
    return tree is not None and tree_is_authority_gated(tree) and not tree_is_one_shot(tree)


def timestamp_latches(ctx: ClaimContext) -> frozenset[_Location]:
    """Scalar ``(var, member)`` latches proven to work as a timed pause (cached). Every conjunct is required:

    - gated readers: entry points holding a mandatory gate closed while the latch is ahead of the clock that neither may
      write the latch nor require it armed (a scalar schedule's ``execute`` does one or the other);
    - no entry point that leaves the latch alone is open only while it is ahead of the clock (a sale or auction window);
    - authority-gated, non-initializer functions both arm it to ``block.timestamp + x`` and clear it: a timer that can
      only run out is a schedule, not a pause;
    - no gated reader touches other state the armers write (a commit/apply timelock stages the value its ``apply``
      reads).

    Mapping-keyed timestamps (timelock ``eta``, per-user cooldowns) never qualify: their writes go through an index, not
    the scalar.
    """
    cached = _TIMESTAMP_LATCHES.get(ctx)
    if cached is not None:
        return cached
    signatures = list(ctx.function_signatures())
    gated: dict[_Location, set[str]] = {}
    opened: dict[_Location, set[str]] = {}
    for signature in signatures:
        tree = ctx.predicate_tree(signature)
        if tree is None:
            continue
        leaves = [leaf for leaf, _path in _mandatory_leaves_with_paths(tree)]
        for leaf in leaves:
            pair = _clock_compared_latch(leaf, _LATCH_BELOW_CLOCK_OPERATORS)
            if pair is not None and not any(_demands_latch_armed(other, pair) for other in leaves):
                gated.setdefault(pair, set()).add(signature)
        for leaf in _iter_leaves(tree):
            pair = _clock_compared_latch(leaf, _LATCH_ABOVE_CLOCK_OPERATORS)
            if pair is not None:
                opened.setdefault(pair, set()).add(signature)
    proven: set[_Location] = set()
    for pair, candidates in gated.items():
        readers = [reader for reader in sorted(candidates) if not _may_write(ctx, reader, pair)]
        if not readers or any(not _may_write(ctx, other, pair) for other in opened.get(pair, ())):
            continue
        writers = [signature for signature in signatures if _authority_writer(ctx, signature)]
        armers = [signature for signature in writers if _LATCH_WRITE_CLOCK_SUM in latch_writes(ctx, signature, pair)]
        if not armers or not any(_LATCH_WRITE_CLEARED in latch_writes(ctx, signature, pair) for signature in writers):
            continue
        # The armer's own body: a reentrancy guard set by its modifier is not state it stages.
        staged = {
            location
            for armer in armers
            for location in _storage_access(ctx, armer, modifiers=False).writes
            if location != pair
        }
        if any(
            _overlaps(location, touched)
            for reader in readers
            for touched in _storage_access(ctx, reader, modifiers=True).refs
            if touched != pair
            for location in staged
        ):
            continue
        proven.add(pair)
    frozen = frozenset(proven)
    _TIMESTAMP_LATCHES[ctx] = frozen
    return frozen


def timestamp_latch_polarity(ctx: ClaimContext, function: str, pair: _Location) -> str | None:
    """``"set"`` (arms to ``block.timestamp + x``), ``"unset"`` (clears), ``"both"``, or ``None`` when this function
    writes the latch neither way.
    """
    writes = latch_writes(ctx, function, pair)
    arms = _LATCH_WRITE_CLOCK_SUM in writes
    clears = _LATCH_WRITE_CLEARED in writes
    if arms and clears:
        return "both"
    if arms:
        return "set"
    if clears:
        return "unset"
    return None


_TOTAL_SUPPLY_SELECTOR = abi_selector("totalSupply()")


def total_supply_vars(ctx: ClaimContext) -> set[str]:
    """State variables published as the ERC-20 ``totalSupply()`` via their auto-getter.

    The ABI entry identifies the supply, not the name; private vars behind a hand-written getter are left to the
    zero-address ``Transfer`` path.
    """
    cached = _TOTAL_SUPPLY_VARS.get(ctx)
    if cached is not None:
        return cached
    found: set[str] = set()
    for variable in getattr(ctx.contract, "state_variables", None) or []:
        if getattr(variable, "visibility", None) != "public":
            continue
        signature = getattr(variable, "solidity_signature", None)
        name = getattr(variable, "name", None)
        if isinstance(signature, str) and isinstance(name, str) and selector_of(signature) == _TOTAL_SUPPLY_SELECTOR:
            found.add(name)
    _TOTAL_SUPPLY_VARS[ctx] = found
    return found


def total_supply_sign(function: Any, supply_vars: set[str]) -> str | None:
    """``"mint"``/``"burn"`` from Binary Addition/Subtraction on a supply variable, following internal/library
    callees (``_mint``/``_burn``).
    """
    if not supply_vars:
        return None
    signs: set[str] = set()
    visited: set[int] = set()

    def walk(unit: Any) -> None:
        if id(unit) in visited:
            return
        visited.add(id(unit))
        for node in getattr(unit, "nodes", []) or []:
            irs = list(getattr(node, "irs", []) or [])
            binary_sign: dict[int, str] = {}
            for ir in irs:
                if type(ir).__name__ != "Binary":
                    continue
                op_type = getattr(getattr(ir, "type", None), "name", "") or ""
                left = _base_name(getattr(getattr(ir, "variable_left", None), "name", None))
                right = _base_name(getattr(getattr(ir, "variable_right", None), "name", None))
                lvalue = getattr(ir, "lvalue", None)
                sign = None
                if op_type == "ADDITION" and (left in supply_vars or right in supply_vars):
                    sign = "mint"
                elif op_type == "SUBTRACTION" and left in supply_vars:
                    sign = "burn"
                if sign is None:
                    continue
                # In place (``totalSupply += x``) or two-step through a TMP stored back.
                if _base_name(getattr(lvalue, "name", None)) in supply_vars:
                    signs.add(sign)
                elif lvalue is not None:
                    binary_sign[id(lvalue)] = sign
            for ir in irs:
                if type(ir).__name__ != "Assignment":
                    continue
                target = _base_name(getattr(getattr(ir, "lvalue", None), "name", None))
                rvalue = getattr(ir, "rvalue", None)
                if target in supply_vars and rvalue is not None and id(rvalue) in binary_sign:
                    signs.add(binary_sign[id(rvalue)])
            for ir in irs:
                if type(ir).__name__ in ("InternalCall", "LibraryCall"):
                    callee = getattr(ir, "function", None)
                    if callee is not None and getattr(callee, "nodes", None):
                        walk(callee)

    walk(function)
    if len(signs) == 1:
        return next(iter(signs))
    return None


def monotone_balance_delta(function: Any) -> str | None:
    """``"mint"``/``"burn"`` when every monotone write to the contract's storage moves one way, else ``None``.

    Resolves references to their state variable, so WETH9's ``balanceOf[msg.sender] += msg.value`` (no supply variable)
    is observed. A ledger move (credit and debit) is ambiguous.
    """
    from slither.core.variables.state_variable import StateVariable

    def state_origin(value: Any) -> Any:
        if isinstance(value, StateVariable):
            return value
        origin = getattr(value, "points_to_origin", None)
        return origin if isinstance(origin, StateVariable) else None

    signs: set[str] = set()
    visited: set[int] = set()

    def walk(unit: Any) -> None:
        if id(unit) in visited:
            return
        visited.add(id(unit))
        for node in getattr(unit, "nodes", []) or []:
            irs = list(getattr(node, "irs", []) or [])
            for ir in irs:
                if type(ir).__name__ != "Binary":
                    continue
                op_type = getattr(getattr(ir, "type", None), "name", "") or ""
                if op_type not in ("ADDITION", "SUBTRACTION"):
                    continue
                if state_origin(getattr(ir, "lvalue", None)) is None:
                    continue
                if state_origin(getattr(ir, "variable_left", None)) is None:
                    continue
                signs.add("mint" if op_type == "ADDITION" else "burn")
            for ir in irs:
                if type(ir).__name__ in ("InternalCall", "LibraryCall"):
                    callee = getattr(ir, "function", None)
                    if callee is not None and getattr(callee, "nodes", None):
                        walk(callee)

    walk(function)
    if len(signs) == 1:
        return next(iter(signs))
    return None


# Rebasing tokens (EETH) track supply under another name, so the zero-address ``Transfer`` is the name-independent
# mint/burn signal.
_ERC20_TRANSFER_ARG_TYPES = ("address", "address", "uint256")


def _is_erc20_transfer_event(ir: Any) -> bool:
    if getattr(ir, "name", None) != "Transfer":
        return False
    args = list(getattr(ir, "arguments", []) or [])
    if len(args) != 3:
        return False
    return tuple(str(getattr(arg, "type", None)) for arg in args) == _ERC20_TRANSFER_ARG_TYPES


def _arg_is_zero(arg: Any, origins: dict[int, tuple[str, str | None]]) -> bool:
    from slither.slithir.variables import Constant

    if isinstance(arg, Constant):
        return getattr(arg, "value", None) in (0, "0", "0x0", False)
    return origins.get(id(arg)) == ("zero", None)


def _transfer_zero_direction(ir: Any, origins: dict[int, tuple[str, str | None]]) -> str | None:
    """``"mint"`` for a canonical ``Transfer`` from the zero address, ``"burn"`` to it, else ``None``."""
    if not _is_erc20_transfer_event(ir):
        return None
    args = list(getattr(ir, "arguments", []) or [])
    from_zero = _arg_is_zero(args[0], origins)
    to_zero = _arg_is_zero(args[1], origins)
    if from_zero and not to_zero:
        return "mint"
    if to_zero and not from_zero:
        return "burn"
    return None


def mint_burn_transfer_sign(function: Any) -> str | None:
    """``"mint"``/``"burn"`` when the function emits a zero-endpoint ``Transfer`` and makes a matching-direction
    monotone write, else ``None``. The write is required so a forwarder re-emitting ``Transfer`` doesn't count;
    emitting both directions is ambiguous. Follows internal/library callees.
    """
    from slither.core.variables.state_variable import StateVariable

    transfer_dirs: set[str] = set()
    write_signs: set[str] = set()
    visited: set[int] = set()

    def walk(unit: Any) -> None:
        if id(unit) in visited:
            return
        visited.add(id(unit))
        origins = _operand_origins(unit)
        for node in getattr(unit, "nodes", []) or []:
            irs = list(getattr(node, "irs", []) or [])
            for ir in irs:
                if type(ir).__name__ == "EventCall":
                    direction = _transfer_zero_direction(ir, origins)
                    if direction:
                        transfer_dirs.add(direction)
            binary_sign: dict[int, str] = {}
            for ir in irs:
                if type(ir).__name__ != "Binary":
                    continue
                op_type = getattr(getattr(ir, "type", None), "name", "") or ""
                left = getattr(ir, "variable_left", None)
                right = getattr(ir, "variable_right", None)
                lvalue = getattr(ir, "lvalue", None)
                sign = None
                if op_type == "ADDITION" and (isinstance(left, StateVariable) or isinstance(right, StateVariable)):
                    sign = "mint"
                elif op_type == "SUBTRACTION" and isinstance(left, StateVariable):
                    sign = "burn"
                if sign is None:
                    continue
                # In place, or two-step through a TMP.
                if isinstance(lvalue, StateVariable):
                    write_signs.add(sign)
                elif lvalue is not None:
                    binary_sign[id(lvalue)] = sign
            for ir in irs:
                if type(ir).__name__ != "Assignment":
                    continue
                target = getattr(ir, "lvalue", None)
                rvalue = getattr(ir, "rvalue", None)
                if isinstance(target, StateVariable) and rvalue is not None and id(rvalue) in binary_sign:
                    write_signs.add(binary_sign[id(rvalue)])
            for ir in irs:
                if type(ir).__name__ in ("InternalCall", "LibraryCall"):
                    callee = getattr(ir, "function", None)
                    if callee is not None and getattr(callee, "nodes", None):
                        walk(callee)

    walk(function)
    if transfer_dirs == {"mint"} and "mint" in write_signs:
        return "mint"
    if transfer_dirs == {"burn"} and "burn" in write_signs:
        return "burn"
    return None


def emits_event_topic(ctx: ClaimContext, function: Any, topic0: str) -> bool:
    """True when ``function`` or a callee it reaches emits the log with ``topic0``.

    Resolved through event declarations, since emitted arguments carry converted types that would hash to a topic never
    logged.
    """
    visited: set[int] = set()

    def walk(unit: Any) -> bool:
        if id(unit) in visited:
            return False
        visited.add(id(unit))
        for node in getattr(unit, "nodes", []) or []:
            irs = list(getattr(node, "irs", []) or [])
            for ir in irs:
                if type(ir).__name__ != "EventCall":
                    continue
                name = getattr(ir, "name", None)
                arity = len(list(getattr(ir, "arguments", []) or []))
                if isinstance(name, str) and ctx.declared_event_topic(name, arity) == topic0:
                    return True
            for ir in irs:
                if type(ir).__name__ in ("InternalCall", "LibraryCall"):
                    callee = getattr(ir, "function", None)
                    if callee is not None and getattr(callee, "nodes", None) and walk(callee):
                        return True
        return False

    return walk(function)


def pointer_write_targets(ctx: ClaimContext, function: str) -> list[Any]:
    """Callable scalar pointer state variables this function writes, as ``StateVariable`` objects for identity
    comparison; the hygiene filter keeps OZ-v5 slot pseudo-variables out.
    """
    normal_names = {write["var"] for write in state_writes(ctx, function) if write.get("hygiene_class") == "normal"}
    if not normal_names:
        return []
    fn = contract_function(ctx, function)
    if fn is None:
        return []
    from slither.core.variables.state_variable import StateVariable

    out = []
    for var in written_state_variables(fn):
        if isinstance(var, StateVariable) and getattr(var, "name", None) in normal_names and is_scalar_pointer(var):
            out.append(var)
    return out


def writes_first_time_set_pointer(ctx: ClaimContext, function: str, pointers: list[Any]) -> bool:
    """True if the function gates a pointer it writes on ``require(pointer == address(0))``: a set-once install, not
    a rotation (latches ``tree_is_one_shot`` doesn't recognize).
    """
    if not pointers:
        return False
    fn = contract_function(ctx, function)
    if fn is None:
        return False
    from slither.slithir.operations import Binary

    pointer_names = {name for p in pointers if isinstance((name := getattr(p, "name", None)), str)}
    origins = _operand_origins(fn)
    for node in getattr(fn, "nodes", []) or []:
        for ir in getattr(node, "irs", []) or []:
            if not isinstance(ir, Binary) or getattr(getattr(ir, "type", None), "name", "") != "EQUAL":
                continue
            left = origins.get(id(getattr(ir, "variable_left", None)))
            right = origins.get(id(getattr(ir, "variable_right", None)))
            sides = {left, right}
            if ("zero", None) in sides and any(side == ("state", name) for name in pointer_names for side in sides):
                return True
    return False


def _operand_origins(fn: Any) -> dict[int, tuple[str, str | None]]:
    """``id(ir_value) -> origin``, folding conversion and assignment chains to a ``("state", name)`` variable or
    ``("zero", None)`` constant.
    """
    from slither.core.variables.state_variable import StateVariable
    from slither.slithir.operations import Assignment, TypeConversion
    from slither.slithir.variables import Constant

    origins: dict[int, tuple[str, str | None]] = {}
    # Nested casts can stack a few links.
    for _ in range(8):
        changed = False
        for node in getattr(fn, "nodes", []) or []:
            for ir in getattr(node, "irs", []) or []:
                lvalue = getattr(ir, "lvalue", None)
                if lvalue is None:
                    continue
                if isinstance(ir, TypeConversion):
                    source = getattr(ir, "variable", None)
                elif isinstance(ir, Assignment):
                    source = getattr(ir, "rvalue", None)
                else:
                    continue
                origin: tuple[str, str | None] | None = None
                if isinstance(source, StateVariable):
                    origin = ("state", getattr(source, "name", None))
                elif isinstance(source, Constant):
                    origin = ("zero", None) if getattr(source, "value", None) in (0, "0", "0x0", False) else None
                elif source is not None:
                    origin = origins.get(id(source))
                if origin is not None and origins.get(id(lvalue)) != origin:
                    origins[id(lvalue)] = origin
                    changed = True
        if not changed:
            break
    return origins


def sibling_invokes_pointer(ctx: ClaimContext, writer: str, pointer: Any) -> str | None:
    """An entry-point sibling that transitively calls ``pointer`` by identity while moving value or writing a
    mapping, or ``None``.
    """
    from slither.core.variables.state_variable import StateVariable
    from slither.slithir.operations import HighLevelCall, LowLevelCall

    if not isinstance(pointer, StateVariable):
        return None

    def resolves_to_pointer(destination: Any) -> bool:
        if destination is pointer:
            return True
        origin = getattr(destination, "points_to_origin", None)
        return origin is pointer

    def calls_pointer(fn: Any, seen: set[int]) -> bool:
        if id(fn) in seen:
            return False
        seen.add(id(fn))
        for node in getattr(fn, "nodes", []) or []:
            for ir in getattr(node, "irs", []) or []:
                if isinstance(ir, (HighLevelCall, LowLevelCall)) and resolves_to_pointer(
                    getattr(ir, "destination", None)
                ):
                    return True
                # Body-origin only: a pointer only reached through a modifier is a guard's authority, not a runtime code
                # pointer.
                if type(ir).__name__ in ("InternalCall", "LibraryCall") and not _is_modifier_call(ir):
                    callee = getattr(ir, "function", None)
                    if callee is not None and getattr(callee, "nodes", None) and calls_pointer(callee, seen):
                        return True
        return False

    for signature in ctx.function_signatures():
        if signature == writer:
            continue
        if not _sibling_moves_value_or_writes_mapping(ctx, signature):
            continue
        if any(calls_pointer(fn, set()) for fn in contract_functions(ctx, signature)):
            return signature
    return None


def _is_modifier_call(ir: Any) -> bool:
    """Modifier calls lead into guard-origin territory, so walks don't follow them."""
    if getattr(ir, "is_modifier_call", False):
        return True
    return type(getattr(ir, "function", None)).__name__ == "Modifier"


def _sibling_moves_value_or_writes_mapping(ctx: ClaimContext, signature: str) -> bool:
    if value_flows(ctx, signature):
        return True
    for write in state_writes(ctx, signature):
        if str(write.get("declared_type") or "").startswith("mapping"):
            return True
    return False
