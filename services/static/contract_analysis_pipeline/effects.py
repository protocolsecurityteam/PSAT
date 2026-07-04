"""Build the semantic ``effects`` artifact for a contract.

Walks Slither IR for every externally-callable function on a contract
and emits a typed record describing the function's *effects*: state
writes, external calls, delegatecalls, contract creations, and
selfdestructs — including those reached transitively through internal
calls. The artifact is the semantic sink/effect carrier for downstream
consumers (``cross_contract.py``, ``tracking.py``,
``effective_permissions.py``).

Why a separate artifact (vs. extending ``predicate_trees``):
``predicate_trees`` deliberately omits *unguarded* functions
(``predicate_artifacts.py:44``) — the resolver treats absence as
"public / unguarded". For sink/effect discovery we want a record per
externally-callable function regardless of guard structure, so a
publicly callable sensitive action (e.g. unprotected ``mint``) is
still surfaced to the policy stage.

Function inclusion:
  * external/public functions: included.
  * constructor: skipped (matches ``predicate_artifacts._is_externally_callable``;
    constructor effects are tracked elsewhere).
  * fallback / receive: INCLUDED. They have real effect semantics —
    receive can hold ETH; fallback often delegatecalls. The
    predicate-tree builder skips them because their "guard" semantics
    are unusual, but that's not a reason to drop them from sink
    discovery.
  * internal / private: never appear directly; their effects are
    surfaced through their external callers via transitive walk.

Plane-0 facts (this artifact is the machine-checkable substrate a later
claims plane reads):
  * every sink carries an ``origin`` — ``body`` for the function's own
    logic, ``guard`` for anything reached only through a modifier. A
    modifier's auth call (``auth.canCall``) is a guard fact, not an
    effect, so it never drives a label.
  * ``state_writes`` records each write at ``var`` / ``member`` /
    ``assembly_slot`` granularity with a ``hygiene_class`` marking the
    non-role writes (constants, ``*StorageLocation`` slot pseudo-vars,
    reentrancy guards, view-function ghost writes).
  * ``value_flows`` records asset movement with a ``from == address(this)``
    direction correction and native ``transfer``/``send`` sinks.
"""

from __future__ import annotations

from typing import Any, TypedDict

from eth_utils.crypto import keccak

from .shared import _all_state_variables
from .summaries import (
    _action_summary,
    _effect_labels,
)

SCHEMA_VERSION = "semantic-2"


class SinkRecord(TypedDict):
    """One sink reachable from a given external function. ``id`` is a
    stable cross-reference; ``function`` is the *originating* external
    function (the entry-point), not the unit where the IR lives — that
    way consumers can group sinks by entry without re-walking
    internal calls. ``origin`` is ``body`` unless the sink is reachable
    only through a modifier (``guard``)."""

    id: str
    function: str
    kind: str  # state_write | external_call | delegatecall | contract_creation | selfdestruct
    target: str
    selector: str | None
    origin: str  # body | guard


class StateWriteFact(TypedDict):
    """A single state write, richer than the ``state_write`` sink: it
    carries member granularity (``accountantState.isPaused`` vs.
    ``accountantState.payoutAddress``) and a hygiene class. Role-fact
    consumers must skip the non-``normal`` classes; they stay recorded as
    raw writes regardless."""

    var: str
    declared_type: str
    member_path: list[str]
    granularity: str  # var | member | assembly_slot
    hygiene_class: str  # normal | constant | storage_location_pseudo | reentrancy_guard | view_writer
    origin: str  # body | guard


class ValueFlow(TypedDict):
    """A value movement fact. ``direction`` is corrected for
    ``from == address(this)`` (a ``transferFrom`` whose sender is the
    contract itself flows *out*, not *in*)."""

    kind: str  # callee_erc20_selector | native_transfer_send | low_level_value_call
    selector: str | None
    direction: str  # in | out
    from_is_self: bool
    origin: str  # body | guard


class EffectInfo(TypedDict):
    function: str
    selector: str
    abi_signature: str
    sinks: list[SinkRecord]
    state_writes: list[StateWriteFact]
    value_flows: list[ValueFlow]
    effects: list[str]
    effect_labels: list[str]
    effect_targets: list[str]
    action_summary: str
    writer_selectors: list[str]
    # True for a selector-bearing external/public, non-view, non-pure entry
    # point (the ABI mutability surface). False for views/pure and for
    # fallback/receive (no selector). The policy stage uses this to surface a
    # state-changing entry point that produced no sink (e.g. an inline-assembly
    # writer) as an honest unsupported row.
    state_changing: bool
    # True when at least one sink on this function originated from inline
    # assembly (sstore/delegatecall lowered to a SolidityCall IR). The gate
    # guarding such a write may itself be inline assembly and therefore
    # invisible to the predicate pipeline, so the policy stage keeps these
    # fail-closed (unsupported) rather than projecting public.
    assembly_state_access: bool


class EffectsArtifact(TypedDict):
    schema_version: str
    contract_name: str | None
    functions: dict[str, EffectInfo]


# ERC-20 pull/send selectors used for value-flow direction facts. ``pull``
# selectors take a ``from`` first argument, so their direction depends on
# whether that argument is ``address(this)``.
_ERC20_PULL_SELECTORS = frozenset(
    {
        "0x23b872dd",  # transferFrom(address,address,uint256)
        "0x42842e0e",  # safeTransferFrom(address,address,uint256)
        "0xb88d4fde",  # safeTransferFrom(address,address,uint256,bytes)
    }
)
_ERC20_SEND_SELECTORS = frozenset(
    {
        "0xa9059cbb",  # transfer(address,uint256)
        "0x423f6cef",  # safeTransfer(address,uint256)
    }
)

# The specific labels an ``external_contract_call`` fact defers to.
_SPECIFIC_EFFECT_LABELS = frozenset(
    {
        "external_contract_call",
        "arbitrary_external_call",
        "asset_send",
        "asset_pull",
        "mint",
        "burn",
        "authority_update",
        "hook_update",
        "ownership_transfer",
        "role_management",
        "pause_toggle",
        "implementation_update",
        "timelock_operation",
        "contract_deployment",
        "delegatecall_execution",
        "selfdestruct_capability",
    }
)


# ---------------------------------------------------------------------------
# Function inclusion (mirrors predicate_artifacts._is_externally_callable but
# keeps fallback/receive — see module docstring).
# ---------------------------------------------------------------------------


def _is_externally_observable(fn: Any) -> bool:
    """External/public OR fallback/receive. Skips constructor and
    internal/private functions."""
    if getattr(fn, "is_constructor", False):
        return False
    if getattr(fn, "is_fallback", False) or getattr(fn, "is_receive", False):
        return True
    name = getattr(fn, "name", "") or ""
    if name == "constructor":
        return False
    if name in ("fallback", "receive"):
        return True
    visibility = getattr(fn, "visibility", None)
    return visibility in ("external", "public")


def _is_state_changing_entry_point(fn: Any) -> bool:
    """A selector-bearing external/public, non-view, non-pure function — the
    ABI mutability surface. Excludes fallback/receive (no selector) and
    view/pure reads."""
    if getattr(fn, "is_fallback", False) or getattr(fn, "is_receive", False):
        return False
    if (getattr(fn, "name", "") or "") in ("fallback", "receive"):
        return False
    if getattr(fn, "visibility", None) not in ("external", "public"):
        return False
    return not (getattr(fn, "view", False) or getattr(fn, "pure", False))


def _is_view_or_pure(fn: Any) -> bool:
    return bool(getattr(fn, "view", False) or getattr(fn, "pure", False))


# ---------------------------------------------------------------------------
# Sink discovery (transitive across internal calls).
# ---------------------------------------------------------------------------


def _node_irs(node: Any) -> list[Any]:
    return list(getattr(node, "irs", []) or [])


def _function_full_name(fn: Any) -> str:
    name = getattr(fn, "full_name", None) or getattr(fn, "name", None) or "<anonymous>"
    return str(name)


def _selector_for(signature: str | None) -> str | None:
    """Compute keccak256[:4] of a canonical ``name(types)`` signature.
    Returns ``None`` if the signature isn't in canonical form (e.g.
    fallback/receive, which have no selector)."""
    if not signature or "(" not in signature or ")" not in signature:
        return None
    return "0x" + keccak(text=signature).hex()[:8]


def _sink_id(function_name: str, kind: str, target: str, idx: int) -> str:
    """Stable, idx-disambiguated ID. The ``idx`` keeps multiple sinks
    of the same (kind, target) on one function distinct (e.g. two
    state_write sinks to the same var from different branches).

    Format is ``<function>:sink<idx>:<kind>:<target>`` so callers can
    reference individual sinks without relying on source order alone."""
    return f"{function_name}:sink{idx}:{kind}:{target}"


def _is_modifier_call(ir: Any) -> bool:
    """True iff ``ir`` is an InternalCall that dispatches a modifier body.
    Everything reached through it is guard-origin, not a real effect."""
    if getattr(ir, "is_modifier_call", False):
        return True
    callee = getattr(ir, "function", None)
    return type(callee).__name__ == "Modifier"


def _node_kind_state_writes(node: Any) -> list[str]:
    """Return the names of state variables written at this node."""
    names: list[str] = []
    for variable in getattr(node, "state_variables_written", []) or []:
        name = getattr(variable, "name", "") or ""
        if name:
            names.append(name)
    return names


def _callee_signature(ir: Any) -> str | None:
    fn = getattr(ir, "function", None)
    for attr in ("full_name", "signature_str"):
        value = getattr(fn, attr, None)
        if isinstance(value, str) and "(" in value and value.endswith(")"):
            return value.rsplit(".", 1)[-1]
    value = getattr(ir, "function_name", None)
    if isinstance(value, str) and "(" in value and value.endswith(")"):
        return value.rsplit(".", 1)[-1]
    return None


def _classify_node_irs(node: Any) -> list[tuple[str, str, str | None]]:
    """Classify the non-state-write sinks at a node. Returns a list of
    ``(kind, target, selector)`` triples.

    State writes are handled separately — Slither's
    ``node.state_variables_written`` is more reliable than walking IR
    assignments by hand."""
    out: list[tuple[str, str, str | None]] = []
    for ir in _node_irs(node):
        op = type(ir).__name__
        if op == "NewContract":
            target = getattr(ir, "contract_name", None) or str(getattr(ir, "contract_created", "")) or "unknown"
            out.append(("contract_creation", str(target), None))
        elif op in ("HighLevelCall", "LibraryCall"):
            destination = getattr(ir, "destination", None)
            destination_name = getattr(destination, "name", None) or str(destination) or "unknown"
            function_name = getattr(ir, "function_name", None) or "call"
            selector = _selector_for(_callee_signature(ir))
            # LibraryCall's "destination" is in its first argument.
            if op == "LibraryCall":
                arguments = list(getattr(ir, "arguments", []) or [])
                if arguments:
                    arg = arguments[0]
                    destination_name = getattr(arg, "name", None) or str(arg) or destination_name
            out.append(("external_call", f"{destination_name}.{function_name}", selector))
        elif op == "LowLevelCall":
            target = getattr(getattr(ir, "destination", None), "name", None) or str(
                getattr(ir, "destination", None) or "unknown"
            )
            function_name = str(getattr(ir, "function_name", "") or "")
            if function_name == "delegatecall":
                out.append(("delegatecall", str(target), None))
            else:
                out.append(("external_call", f"{target}.{function_name or 'call'}", None))
        elif op == "SolidityCall":
            function_name = getattr(getattr(ir, "function", None), "name", "") or ""
            arguments = list(getattr(ir, "arguments", []) or [])
            if function_name.startswith("selfdestruct("):
                out.append(("selfdestruct", "selfdestruct", None))
            elif function_name.startswith("sstore("):
                # Inline-assembly storage write. Slither does not populate
                # node.state_variables_written for assembly, so this is the
                # only place the write is visible. Key the sink by the slot
                # literal/expr; slot->named-var resolution is a separate concern.
                slot = str(arguments[0]) if arguments else "unknown"
                out.append(("state_write", f"assembly_storage:{slot}", None))
            elif function_name.startswith("delegatecall("):
                # Inline-assembly delegatecall, e.g. an EIP-1967 proxy fallback.
                # Signature: delegatecall(gas, addr, inOff, inLen, outOff, outLen).
                target = str(arguments[1]) if len(arguments) > 1 else "assembly_delegatecall"
                out.append(("delegatecall", f"assembly_delegatecall:{target}", None))
    return out


def _walk_unit_for_sinks(
    unit: Any,
    visited: set[Any],
    origin: str,
) -> list[tuple[str, str, str | None, str]]:
    """Recursively gather ``(kind, target, selector, origin)`` sink tuples
    from ``unit`` and any internal/library/modifier callees. ``origin``
    flips to ``guard`` the moment the walk steps through a modifier call and
    stays there for the rest of that subtree. De-dup happens at the caller
    level so distinct indices are preserved."""
    unit_key = getattr(unit, "canonical_name", None) or getattr(unit, "full_name", None) or id(unit)
    if unit_key in visited:
        return []
    visited.add(unit_key)

    found: list[tuple[str, str, str | None, str]] = []
    for node in getattr(unit, "nodes", []) or []:
        for var_name in _node_kind_state_writes(node):
            found.append(("state_write", var_name, None, origin))
        for kind, target, selector in _classify_node_irs(node):
            found.append((kind, target, selector, origin))
        # Recurse into internal/library callees so transitive writes
        # surface on the entry-point's record.
        for ir in _node_irs(node):
            op = type(ir).__name__
            if op not in ("InternalCall", "LibraryCall"):
                continue
            callee = getattr(ir, "function", None)
            if callee is None or not getattr(callee, "nodes", None):
                continue
            child_origin = "guard" if (origin == "guard" or _is_modifier_call(ir)) else "body"
            found.extend(_walk_unit_for_sinks(callee, visited, child_origin))
    return found


def _build_sink_records(function: Any) -> list[SinkRecord]:
    """One sink per (kind, target) pair we discover, transitively
    deduped while preserving order. A sink reachable through both the body
    and a guard keeps ``origin=body`` (a real effect wins). The selector
    field is per-sink: only ``external_call`` sinks carry one, and only
    when Slither exposes the called function's canonical signature."""
    function_name = _function_full_name(function)
    quads = _walk_unit_for_sinks(function, set(), "body")

    out: list[SinkRecord] = []
    index: dict[tuple[str, str, str | None], int] = {}
    for kind, target, selector, origin in quads:
        key = (kind, target, selector)
        if key in index:
            if origin == "body":
                out[index[key]]["origin"] = "body"
            continue
        idx = len(out)
        record: SinkRecord = {
            "id": _sink_id(function_name, kind, target, idx),
            "function": function_name,
            "kind": kind,
            "target": target,
            "selector": selector,
            "origin": origin,
        }
        index[key] = idx
        out.append(record)
    return out


# ---------------------------------------------------------------------------
# State-write facts (member paths + hygiene classes).
# ---------------------------------------------------------------------------


def _struct_member_types(state_variables: list[Any]) -> dict[str, dict[str, str]]:
    """``{var_name: {member_name: declared_type}}`` for struct-typed state
    vars, read from Slither's structure ``elems``."""
    out: dict[str, dict[str, str]] = {}
    for variable in state_variables:
        declared = getattr(variable, "type", None)
        structure = getattr(declared, "type", None)
        elems = getattr(structure, "elems", None)
        if isinstance(elems, dict):
            name = getattr(variable, "name", "") or ""
            out[name] = {member: str(getattr(value, "type", "") or "") for member, value in elems.items()}
    return out


def _transitive_member_writes(function: Any, wanted: set[str]) -> dict[str, set[str]]:
    """``{var_name: {member}}`` — member-level writes into the ``wanted``
    base state vars, tracked by pairing a ``Member`` IR (``$.member``) with
    the ``Assignment`` that writes the reference it produced. Walks the same
    internal/library/modifier callees as sink discovery."""
    out: dict[str, set[str]] = {}
    visited: set[int] = set()

    def walk(unit: Any) -> None:
        key = id(unit)
        if key in visited:
            return
        visited.add(key)
        ref_to_pair: dict[int, tuple[str, str]] = {}
        for node in getattr(unit, "nodes", []) or []:
            for ir in _node_irs(node):
                op = type(ir).__name__
                if op == "Member":
                    base = getattr(ir, "variable_left", None)
                    base_name = getattr(base, "name", None)
                    member = getattr(ir, "variable_right", None)
                    member_name = getattr(member, "name", None) or str(member)
                    lvalue = getattr(ir, "lvalue", None)
                    if isinstance(base_name, str) and base_name in wanted and lvalue is not None:
                        ref_to_pair[id(lvalue)] = (base_name, str(member_name))
                elif op == "Assignment":
                    lvalue = getattr(ir, "lvalue", None)
                    if lvalue is not None and id(lvalue) in ref_to_pair:
                        base_name, member_name = ref_to_pair[id(lvalue)]
                        out.setdefault(base_name, set()).add(member_name)
        for node in getattr(unit, "nodes", []) or []:
            for ir in _node_irs(node):
                if type(ir).__name__ not in ("InternalCall", "LibraryCall"):
                    continue
                callee = getattr(ir, "function", None)
                if callee is not None and getattr(callee, "nodes", None):
                    walk(callee)

    walk(function)
    return out


def _looks_like_storage_location(name: str) -> bool:
    low = name.lower()
    return "storagelocation" in low or low.endswith("_slot") or low.endswith("slot") or low.endswith("_storage")


_REENTRANCY_GUARD_NAMES = frozenset(
    {"_status", "_reentrancyguard", "_reentrancystatus", "reentrancylock", "_locked", "locked", "_lock"}
)


def _is_reentrancy_guard_var(variable: Any) -> bool:
    name = (getattr(variable, "name", "") or "").lower()
    if not name:
        return False
    return "reentran" in name or name in _REENTRANCY_GUARD_NAMES


def _hygiene_class_for_var(variable: Any, function: Any) -> str:
    """Classify a write for role-fact hygiene. A view/pure function that
    "writes" is a Slither attribution ghost (OZ v5 namespaced getters);
    ``*StorageLocation`` / ``*_SLOT`` bytes32 constants are slot pseudo-vars,
    not the value they point at; reentrancy guards are control noise. All
    of these must be excluded from role facts but remain raw writes."""
    if _is_view_or_pure(function):
        return "view_writer"
    if variable is None:
        return "normal"
    type_str = str(getattr(variable, "type", "") or "")
    name = getattr(variable, "name", "") or ""
    if bool(getattr(variable, "is_constant", False)):
        if type_str == "bytes32" and _looks_like_storage_location(name):
            return "storage_location_pseudo"
        return "constant"
    if _is_reentrancy_guard_var(variable):
        return "reentrancy_guard"
    return "normal"


def _state_write_facts(function: Any, sinks: list[SinkRecord]) -> list[StateWriteFact]:
    """Project the ``state_write`` sinks into richer facts: member
    granularity for struct writes, declared types, and hygiene classes."""
    contract = getattr(function, "contract", None)
    state_variables = _all_state_variables(contract) if contract is not None else []
    by_name = {getattr(variable, "name", ""): variable for variable in state_variables}
    member_types = _struct_member_types(state_variables)

    write_sinks = [s for s in sinks if s["kind"] == "state_write"]
    wanted = {s["target"] for s in write_sinks if not s["target"].startswith("assembly_storage:")}
    member_writes = _transitive_member_writes(function, wanted) if wanted else {}

    facts: list[StateWriteFact] = []
    for sink in write_sinks:
        target = sink["target"]
        origin = sink.get("origin", "body")
        if target.startswith("assembly_storage:"):
            facts.append(
                {
                    "var": target,
                    "declared_type": "",
                    "member_path": [],
                    "granularity": "assembly_slot",
                    "hygiene_class": "view_writer" if _is_view_or_pure(function) else "normal",
                    "origin": origin,
                }
            )
            continue
        variable = by_name.get(target)
        hygiene = _hygiene_class_for_var(variable, function)
        declared_type = str(getattr(variable, "type", "") or "")
        members = member_writes.get(target)
        if members:
            for member in sorted(members):
                facts.append(
                    {
                        "var": target,
                        "declared_type": member_types.get(target, {}).get(member) or declared_type,
                        "member_path": [member],
                        "granularity": "member",
                        "hygiene_class": hygiene,
                        "origin": origin,
                    }
                )
        else:
            facts.append(
                {
                    "var": target,
                    "declared_type": declared_type,
                    "member_path": [],
                    "granularity": "var",
                    "hygiene_class": hygiene,
                    "origin": origin,
                }
            )
    return facts


# ---------------------------------------------------------------------------
# Value-flow facts (direction correction + native transfer/send sinks).
# ---------------------------------------------------------------------------


def _arg_is_address_this(arg: Any, this_ids: set[int], this_names: set[str]) -> bool:
    if arg is None:
        return False
    if getattr(arg, "name", None) == "this":
        return True
    if id(arg) in this_ids:
        return True
    name = getattr(arg, "name", None)
    return isinstance(name, str) and name in this_names


def _value_flow_facts(function: Any) -> list[ValueFlow]:
    """Value movement facts, transitively. ``transferFrom`` whose ``from``
    is ``address(this)`` flows *out*; native ``transfer``/``send`` are value
    sinks Slither lowers to their own IR op (not a low-level call)."""
    flows: list[ValueFlow] = []
    seen: set[tuple[str, str | None, str, bool, str]] = set()
    visited: set[int] = set()

    def add(flow: ValueFlow) -> None:
        key = (flow["kind"], flow["selector"], flow["direction"], flow["from_is_self"], flow["origin"])
        if key in seen:
            return
        seen.add(key)
        flows.append(flow)

    def walk(unit: Any, origin: str) -> None:
        key = id(unit)
        if key in visited:
            return
        visited.add(key)

        this_ids: set[int] = set()
        this_names: set[str] = set()
        for node in getattr(unit, "nodes", []) or []:
            for ir in _node_irs(node):
                if type(ir).__name__ != "TypeConversion":
                    continue
                source = getattr(ir, "variable", None)
                if getattr(source, "name", None) == "this":
                    lvalue = getattr(ir, "lvalue", None)
                    if lvalue is not None:
                        this_ids.add(id(lvalue))
                        name = getattr(lvalue, "name", None)
                        if isinstance(name, str):
                            this_names.add(name)

        for node in getattr(unit, "nodes", []) or []:
            for ir in _node_irs(node):
                op = type(ir).__name__
                if op in ("Transfer", "Send"):
                    add(
                        {
                            "kind": "native_transfer_send",
                            "selector": None,
                            "direction": "out",
                            "from_is_self": True,
                            "origin": origin,
                        }
                    )
                elif op == "HighLevelCall":
                    selector = _selector_for(_callee_signature(ir))
                    if selector in _ERC20_PULL_SELECTORS:
                        arguments = list(getattr(ir, "arguments", []) or [])
                        from_arg = arguments[0] if arguments else None
                        from_self = _arg_is_address_this(from_arg, this_ids, this_names)
                        add(
                            {
                                "kind": "callee_erc20_selector",
                                "selector": selector,
                                "direction": "out" if from_self else "in",
                                "from_is_self": from_self,
                                "origin": origin,
                            }
                        )
                    elif selector in _ERC20_SEND_SELECTORS:
                        add(
                            {
                                "kind": "callee_erc20_selector",
                                "selector": selector,
                                "direction": "out",
                                "from_is_self": True,
                                "origin": origin,
                            }
                        )
                elif op == "LowLevelCall" and "value:" in str(ir):
                    add(
                        {
                            "kind": "low_level_value_call",
                            "selector": None,
                            "direction": "out",
                            "from_is_self": True,
                            "origin": origin,
                        }
                    )
                if op in ("InternalCall", "LibraryCall"):
                    callee = getattr(ir, "function", None)
                    if callee is not None and getattr(callee, "nodes", None):
                        child_origin = "guard" if (origin == "guard" or _is_modifier_call(ir)) else "body"
                        walk(callee, child_origin)

    walk(function, "body")
    return flows


# ---------------------------------------------------------------------------
# Effects + labels + writer selectors per function.
# ---------------------------------------------------------------------------


def _effect_targets_from_sinks(sinks: list[SinkRecord]) -> list[str]:
    """Compatibility display targets sourced from the sink list.

    State writes and external-call dotted targets both remain here because
    API/UI consumers already render this field. Semantic consumers should
    read ``sinks`` and selectors directly.
    """
    seen: list[str] = []
    seen_set: set[str] = set()
    for sink in sinks:
        if sink["kind"] == "state_write" and sink["target"] not in seen_set:
            seen.append(sink["target"])
            seen_set.add(sink["target"])
        elif sink["kind"] == "external_call" and sink["target"] not in seen_set:
            # Kept for API/UI compatibility; label inference reads the
            # selector-bearing sink records instead.
            seen.append(sink["target"])
            seen_set.add(sink["target"])
    return seen


def _writer_selectors_for(function: Any, sinks: list[SinkRecord]) -> list[str]:
    """For a state-write function, its own selector is the relevant
    writer selector (HyperSync replays this function to attribute the
    write). Returns a list because some pipelines accumulate multiple
    selectors per logical writer (overloads)."""
    has_state_write = any(s["kind"] == "state_write" for s in sinks)
    if not has_state_write:
        return []
    signature = _function_full_name(function)
    selector = _selector_for(signature)
    if selector is None:
        return []
    return [selector]


def _reconcile_value_flow_labels(labels: list[str], value_flows: list[ValueFlow]) -> list[str]:
    """Correct asset-direction labels from the value-flow facts. Native
    transfer/send is an outbound value sink Slither's low-level scan misses;
    a ``transferFrom`` whose ``from`` is ``address(this)`` was mis-read as a
    pull. Only body-origin flows count."""
    body_flows = [vf for vf in value_flows if vf["origin"] != "guard"]
    if not body_flows:
        return labels

    if any(vf["kind"] == "native_transfer_send" for vf in body_flows):
        labels = [lbl for lbl in labels if lbl != "hook_update"]
        if "asset_send" not in labels:
            labels.append("asset_send")

    pull_from_self = any(
        vf["kind"] == "callee_erc20_selector" and vf["from_is_self"] and vf["selector"] in _ERC20_PULL_SELECTORS
        for vf in body_flows
    )
    genuine_pull = any(
        vf["kind"] == "callee_erc20_selector" and not vf["from_is_self"] and vf["selector"] in _ERC20_PULL_SELECTORS
        for vf in body_flows
    )
    if pull_from_self and not genuine_pull and "asset_pull" in labels:
        labels = [lbl for lbl in labels if lbl != "asset_pull"]
        if "asset_send" not in labels:
            labels.append("asset_send")
    return labels


def _effect_info_for_function(function: Any) -> EffectInfo:
    sinks = _build_sink_records(function)
    state_writes = _state_write_facts(function, sinks)
    value_flows = _value_flow_facts(function)
    effects: list[str] = []

    # Guard-origin sinks (a modifier's own auth call, a reentrancy latch) are
    # facts, not effects: they never drive a label, a display target, or a
    # summary. They stay in ``sinks`` with ``origin=guard``.
    body_sinks = [s for s in sinks if s["origin"] != "guard"]

    # ``effect_targets`` remains a compatibility display field. Semantic
    # consumers should read ``sinks`` and selectors instead.
    effect_targets = _effect_targets_from_sinks(body_sinks)

    # _effect_labels takes a synthetic graph-entry analog. Capability
    # reachability (delegatecall_execution, selfdestruct_capability,
    # contract_deployment) keys on ``sink_kinds`` over *all* sinks — a
    # delegatecall reachable only through a proxy's ``ifAdmin`` modifier is
    # still reachable. The external-call/asset layer reads the body-only sink
    # list, so a modifier's own auth call can't drive an effect label.
    sink_kinds = sorted({s["kind"] for s in sinks})
    effect_context = {
        "effects": list(effects),
        "effect_targets": list(effect_targets),
        "sink_kinds": sink_kinds,
        "sinks": list(body_sinks),
    }
    labels = _effect_labels(function, effect_context)
    # Functions with body external_call sinks but no specific (mint/burn/asset/etc)
    # label get ``external_contract_call`` directly from the sink shape.
    has_external_call = any(s["kind"] == "external_call" for s in body_sinks)
    if has_external_call and not any(lbl in _SPECIFIC_EFFECT_LABELS for lbl in labels):
        labels.append("external_contract_call")
    labels = _reconcile_value_flow_labels(labels, value_flows)
    summary = _action_summary(labels, list(effect_targets))

    signature = _function_full_name(function)
    selector = _selector_for(signature) or ""
    return {
        "function": signature,
        "selector": selector,
        "abi_signature": signature,
        "sinks": sinks,
        "state_writes": state_writes,
        "value_flows": value_flows,
        "effects": list(effects),
        "effect_labels": list(labels),
        # Includes both state-write var names and external-call dotted
        # targets for label/summary rendering. Tracking.py reads ``sinks``
        # directly to enumerate state_write writers.
        "effect_targets": list(effect_targets),
        "action_summary": summary,
        "writer_selectors": _writer_selectors_for(function, sinks),
        "state_changing": _is_state_changing_entry_point(function),
        "assembly_state_access": any(
            s["kind"] in ("state_write", "delegatecall")
            and (s["target"].startswith("assembly_storage:") or s["target"].startswith("assembly_delegatecall:"))
            for s in sinks
        ),
    }


# ---------------------------------------------------------------------------
# Top-level entry.
# ---------------------------------------------------------------------------


def _record_prefers(new_info: EffectInfo, new_fn: Any, old_info: EffectInfo, old_fn: Any) -> bool:
    """Should ``new_info`` replace ``old_info`` for the same signature?

    Two functions can share a ``full_name`` — a concrete implementation and
    an inherited interface/abstract re-declaration (0 nodes). Keying the dict
    by ``full_name`` alone lets the 0-node record clobber the real one and
    blank its sinks (EigenLayer StrategyManager ``pause``). Prefer the
    implemented body, then the one carrying more sinks."""
    new_impl = bool(getattr(new_fn, "is_implemented", False)) and bool(getattr(new_fn, "nodes", None))
    old_impl = bool(getattr(old_fn, "is_implemented", False)) and bool(getattr(old_fn, "nodes", None))
    if new_impl != old_impl:
        return new_impl
    return len(new_info["sinks"]) > len(old_info["sinks"])


def build_effects(contract: Any) -> EffectsArtifact:
    """Return the ``effects`` artifact for ``contract``: one
    ``EffectInfo`` per externally-observable function (external,
    public, fallback, receive)."""
    functions: dict[str, EffectInfo] = {}
    chosen_fn: dict[str, Any] = {}
    for fn in getattr(contract, "functions", []) or []:
        if not _is_externally_observable(fn):
            continue
        info = _effect_info_for_function(fn)
        signature = info["function"]
        existing = functions.get(signature)
        if existing is None or _record_prefers(info, fn, existing, chosen_fn[signature]):
            functions[signature] = info
            chosen_fn[signature] = fn

    return {
        "schema_version": SCHEMA_VERSION,
        "contract_name": getattr(contract, "name", None),
        "functions": functions,
    }
