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

from typing import Any, TypedDict, cast
from weakref import WeakKeyDictionary

from eth_utils.crypto import keccak
from typing_extensions import NotRequired

from .provenance import ProvenanceEngine, is_top
from .shared import _all_state_variables
from .summaries import (
    _action_summary,
    _effect_labels,
)
from .token_slots import derive_token_slots

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


class KindTier(TypedDict):
    """A lattice classification with the tier at which it was witnessed.

    ``tier`` is ``dispositive_ast`` (scoring Tier 1) when the classified SSA
    operand is *directly* a StateVariable / parameter / ``msg.sender`` / literal
    — a definitive AST fact — and ``static_trace`` (scoring Tier 2) when it was
    recovered through the SSA provenance trace (casts, member reads). The
    ``indeterminate`` kind always carries ``static_trace``: it is an inference
    conclusion (TOP / empty / cross-branch MIX), never a dispositive fact."""

    kind: str
    tier: str  # dispositive_ast | static_trace


class ValueFlow(TypedDict):
    """A value movement fact. ``direction`` is corrected for
    ``from == address(this)`` (a ``transferFrom`` whose sender is the
    contract itself flows *out*, not *in*).

    ``target_kind`` / ``amount_kind`` classify *where the funds go* and *how
    much can leave* — the theft-vs-routing discriminators. They are the union
    of every contributing IR site's classification collapsed to a single
    unambiguous origin (or ``indeterminate`` on any MIX), so a caller-chosen
    destination and an immutable one no longer produce identical witnesses."""

    kind: str  # callee_erc20_selector | native_transfer_send | low_level_value_call
    selector: str | None
    direction: str  # in | out
    from_is_self: bool
    origin: str  # body | guard
    # target_kind ∈ {immutable, constant, storage_no_setter, storage_setter,
    #   param, msg_sender, caller_controlled, self, token_owner, indeterminate}
    target_kind: NotRequired[KindTier]
    # amount_kind ∈ {msg_value, param, whole_balance, bounded_by_storage,
    #   fixed_constant, balance_delta, indeterminate}
    amount_kind: NotRequired[KindTier]
    # Positional index of the ENTRY function's parameter the destination
    # resolves to. Present ONLY when ``target_kind`` is ``param`` and every
    # contributing site agrees on that one parameter slot; a struct member or
    # array element of a parameter never emits one (the value is not the whole
    # argument). Consumers plant a probe address in that ABI slot, so a guessed
    # index would probe the wrong argument — absent means "do not guess".
    target_param_index: NotRequired[int]


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


class TokenSlotEntry(TypedDict):
    """Storage base slot of a token-precondition mapping, keyed to the VIEW
    getter that reads it back. Consumed by the effects stage to seed
    balance/allowance/shares/ownership on an anvil fork (see ``token_slots``)."""

    getter: str  # canonical signature of a direct-read view getter (read-back anchor)
    role: str  # balance | allowance | shares | owner
    key_kind: str  # address | address_address | uint256
    base_slot: str  # 0x-padded 32-byte base slot of the mapping variable
    derivation: str  # storage_layout | oz_v5_namespaced
    variable: str | None


class TokenSlots(TypedDict):
    entries: list[TokenSlotEntry]


class EffectsArtifact(TypedDict):
    schema_version: str
    contract_name: str | None
    functions: dict[str, EffectInfo]
    token_slots: NotRequired[TokenSlots]


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


def _base_name(name: Any) -> str | None:
    """Strip Slither's SSA version suffix (``dest_1`` -> ``dest``). The
    provenance engine keys locals by their *base* name, so version suffixes
    must be normalized before a set-membership test against it."""
    if not isinstance(name, str):
        return None
    parts = name.rsplit("_", 1)
    if len(parts) == 2 and parts[1].isdigit():
        return parts[0]
    return name


# Contract-level setter set: state vars written by any non-constructor function
# body, as Slither attributes writes. A setter's *existence* is a dispositive
# fact. Its *absence* is only a sound proof that a non-immutable var cannot be
# redirected post-deploy when the scan is DISPOSITIVELY COMPLETE — i.e. Slither
# attributed every write in the contract's code. Two blind spots break that
# precondition and are checked by ``_setter_scan_complete``: a raw/computed-slot
# ``sstore`` (Slither attributes ``x.slot`` writes to ``x`` but not
# ``sstore(0, …)`` / keccak-slot writes), and any ``delegatecall`` (foreign code
# can write any slot as this contract). When the scan is incomplete, "no setter"
# degrades to ``indeterminate`` — never a proven-negative "fixed destination".
# A third blind spot — storage-pointer aliasing — is resolved separately by
# ``_aliased_storage_writes``: a state var written only through a callee taking a
# ``storage`` reference (``using X for`` / library / internal storage-lib idiom)
# is not attributed by ``all_state_variables_written`` either. We follow the
# aliasing to attribute the write back to its origin var (a real setter), and
# only fall back to indeterminate for the aliases we genuinely cannot resolve.
# Memoized per contract for the build pass.
_SETTER_VARS: WeakKeyDictionary[Any, set[str]] = WeakKeyDictionary()
_SETTER_SCAN_COMPLETE: WeakKeyDictionary[Any, bool] = WeakKeyDictionary()
_ALIASED_WRITES: WeakKeyDictionary[Any, tuple[set[str], set[str], bool]] = WeakKeyDictionary()

# Recursion depth for following a storage reference through forwarding callees.
_STORAGE_ALIAS_DEPTH = 6


def _setter_state_vars(contract: Any) -> set[str]:
    cached = _SETTER_VARS.get(contract)
    if cached is not None:
        return cached
    setters: set[str] = set()
    for fn in getattr(contract, "functions", []) or []:
        if getattr(fn, "is_constructor", False):
            continue
        try:
            written = fn.all_state_variables_written()
        except Exception:  # pragma: no cover - slither edge
            written = []
        for var in written or []:
            name = getattr(var, "name", None)
            if name:
                setters.add(name)
    # Storage-pointer-aliased writes Slither did not attribute, resolved back to
    # their origin state var — these are real, redirecting setters.
    setters |= _aliased_storage_writes(contract)[0]
    _SETTER_VARS[contract] = setters
    return setters


def _arg_is_param(arg: Any, param: Any) -> bool:
    if arg is param:
        return True
    pname = getattr(param, "name", None)
    return bool(pname) and getattr(arg, "name", None) == pname


def _storage_param_write_status(callee: Any, param: Any, depth: int = 0, seen: set[int] | None = None) -> str:
    """Whether ``callee`` writes through its storage-reference parameter
    ``param`` — directly (``param.field = …`` / ``param[…] = …``, which puts
    ``param`` in the callee's ``variables_written``) or transitively (forwarding
    ``param`` into another storage-writing callee). Returns ``writes`` /
    ``reads_only`` / ``unresolved`` (callee body absent — cannot decide)."""
    if callee is None or not getattr(callee, "nodes", None):
        return "unresolved"
    if depth > _STORAGE_ALIAS_DEPTH:
        return "unresolved"
    seen = seen if seen is not None else set()
    if id(callee) in seen:
        # A recursion cycle: we cannot see whether the write happens down the
        # recursive tail. Fail toward unresolved (-> indeterminate), never
        # reads_only — that would let a genuinely-redirected var read as a
        # proven-fixed "no setter".
        return "unresolved"
    seen.add(id(callee))
    pname = getattr(param, "name", None)
    for written in getattr(callee, "variables_written", []) or []:
        if written is param or (pname and getattr(written, "name", None) == pname):
            return "writes"
    status = "reads_only"
    for node in getattr(callee, "nodes", []) or []:
        for ir in _node_irs(node):
            if type(ir).__name__ not in ("InternalCall", "LibraryCall"):
                continue
            sub = getattr(ir, "function", None)
            subparams = list(getattr(sub, "parameters", []) or [])
            for sub_param, arg in zip(subparams, getattr(ir, "arguments", []) or []):
                if not getattr(sub_param, "is_storage", False) or not _arg_is_param(arg, param):
                    continue
                result = _storage_param_write_status(sub, sub_param, depth + 1, seen)
                if result == "writes":
                    return "writes"
                if result == "unresolved":
                    status = "unresolved"
    return status


def _resolve_storage_origin(arg: Any, function: Any, seen: set[str] | None = None) -> str | None:
    """The origin state-variable NAME a storage-reference argument aliases, or
    ``None`` when it cannot be tied to a single declared state var. Handles a
    direct state var and a local storage pointer assigned from a state var or a
    member/index of one (``Box storage b = box;`` / ``= boxes[k];``). A pointer
    sourced from a call return is unresolvable — ``None``."""
    from slither.core.variables.state_variable import StateVariable  # type: ignore[import]

    if isinstance(arg, StateVariable):
        return getattr(arg, "name", None)
    aname = getattr(arg, "name", None)
    if not aname:
        return None
    seen = seen if seen is not None else set()
    if aname in seen:
        return None
    seen.add(aname)
    for node in getattr(function, "nodes", []) or []:
        for ir in _node_irs(node):
            lvalue = getattr(ir, "lvalue", None)
            if lvalue is None or getattr(lvalue, "name", None) != aname:
                continue
            tn = type(ir).__name__
            if tn == "Assignment":
                return _resolve_storage_origin(getattr(ir, "rvalue", None), function, seen)
            if tn in ("Member", "Index"):
                base = getattr(ir, "variable_left", None)
                if isinstance(base, StateVariable):
                    return getattr(base, "name", None)
                return _resolve_storage_origin(base, function, seen)
            return None  # call-sourced / cast / other — not a single state var
    return None


def _aliased_storage_writes(contract: Any) -> tuple[set[str], set[str], bool]:
    """Resolve storage-pointer aliasing the attributed-write scan misses.

    Returns ``(resolved_setters, indeterminate_vars, contract_unresolvable)``:
    * ``resolved_setters`` — origin state vars written through a storage-ref
      alias that resolved to a definite variable: real setters (-> storage_setter).
    * ``indeterminate_vars`` — origin vars aliased into a callee whose
      write-through status couldn't be decided; their no-setter proof is unsound
      so they degrade to indeterminate (not storage_no_setter).
    * ``contract_unresolvable`` — a write-through alias whose origin var itself
      couldn't be resolved (unknown which var was redirected): no no-setter proof
      in the contract is sound, so the whole scan is incomplete.
    """
    cached = _ALIASED_WRITES.get(contract)
    if cached is not None:
        return cached
    resolved: set[str] = set()
    indeterminate: set[str] = set()
    contract_unresolvable = False
    for fn in getattr(contract, "functions", []) or []:
        if getattr(fn, "is_constructor", False):
            continue
        for node in getattr(fn, "nodes", []) or []:
            for ir in _node_irs(node):
                if type(ir).__name__ not in ("InternalCall", "LibraryCall"):
                    continue
                callee = getattr(ir, "function", None)
                params = list(getattr(callee, "parameters", []) or [])
                for param, arg in zip(params, getattr(ir, "arguments", []) or []):
                    if not getattr(param, "is_storage", False):
                        continue
                    status = _storage_param_write_status(callee, param)
                    if status == "reads_only":
                        continue
                    origin = _resolve_storage_origin(arg, fn)
                    if origin is None:
                        contract_unresolvable = True
                    elif status == "writes":
                        resolved.add(origin)
                    else:  # "unresolved" — might write, cannot decide for this origin
                        indeterminate.add(origin)
    result = (resolved, indeterminate, contract_unresolvable)
    _ALIASED_WRITES[contract] = result
    return result


def _setter_scan_complete(contract: Any) -> bool:
    """True iff Slither's write attribution is exhaustive for this contract, so
    the *absence* of a setter is dispositive. False when a value could be
    written through a channel the attributed-write scan cannot see:

    * an unattributed assembly ``sstore`` — Slither lowers ``sstore(x.slot, …)``
      to an attributed write of ``x`` (no ``sstore`` IR survives), so a residual
      ``SolidityCall sstore(...)`` IR is exactly the raw-numeric / computed-slot
      write it could not attribute;
    * a ``delegatecall`` / ``callcode`` — foreign code executes in this
      contract's storage context and may write any slot;
    * a storage-pointer alias written through a callee whose ORIGIN state var
      could not be resolved (``_aliased_storage_writes`` third element) — some
      unknown var was redirected.

    Modifiers are scanned too (assembly can live in a guard body). Memoized."""
    cached = _SETTER_SCAN_COMPLETE.get(contract)
    if cached is not None:
        return cached
    if _aliased_storage_writes(contract)[2]:
        _SETTER_SCAN_COMPLETE[contract] = False
        return False
    units = list(getattr(contract, "functions", []) or []) + list(getattr(contract, "modifiers", []) or [])
    complete = True
    for unit in units:
        if not complete:
            break
        for node in getattr(unit, "nodes", []) or []:
            for ir in _node_irs(node):
                tn = type(ir).__name__
                if tn == "LowLevelCall":
                    if getattr(ir, "function_name", None) in ("delegatecall", "callcode"):
                        complete = False
                        break
                elif tn == "SolidityCall":
                    name = getattr(getattr(ir, "function", None), "name", "") or ""
                    if name.startswith(("sstore(", "delegatecall(", "callcode(")):
                        complete = False
                        break
            if not complete:
                break
    _SETTER_SCAN_COMPLETE[contract] = complete
    return complete


class _UnitCtx:
    """Per-walked-unit classification context for value-flow destinations and
    amounts. Carries the unit's provenance map plus the two soundness guards:

    * ``merged`` — base names of LOCAL variables that a Phi merges across
      branches. The engine keys locals by base name, so two branch versions of
      ``d`` (``d = cond ? who : feeSink``) collapse to whichever assignment was
      processed last — silently discarding the other origin. Any destination
      that reaches such a base is forced ``indeterminate`` rather than trusting
      the collapsed value. (State-variable entrypoint Phis are excluded: their
      incoming versions are the same origin, not a cross-branch merge.)
    * ``nested`` — True when the unit is an internal callee, not the entry
      point. A ``parameter`` origin inside a callee is not self-evidently
      caller-directed: the entry may forward a fixed state var OR a
      caller-chosen argument into it. But the value-flow walk is rooted at ONE
      external entry, so the argument forwarded at each call site along that
      single path is unambiguous. ``param_bindings`` carries that forwarded
      origin (see below); a nested ``parameter`` is resolved through it to the
      entry-rooted kind, and only degrades to ``indeterminate`` when the
      binding is missing, unresolvable, or divergent across call sites. A state
      var / ``msg.sender`` / constant is contract-global and stays trustworthy
      across the internal-call boundary regardless.
    * ``param_bindings`` — for a nested unit, maps each of the unit's formal
      parameter base names to the *neutral origin* (see ``_arg_origin``) the
      entry-rooted walk forwarded into it at this call site: an entry parameter,
      ``msg.sender``, ``tx.origin``, ``address(this)``, a constant, or a named
      state variable. ``None`` on the entry itself (its own parameters ARE the
      caller-directed origin). Threaded down ``walk`` per call site; a helper
      reached from two sites with divergent bindings is re-walked so the
      cross-site fold collapses the disagreement to ``indeterminate``.
    * ``param_index_bindings`` — the positional half of ``param_bindings``: for a
      nested unit, the ENTRY parameter INDEX each formal binds to, present only
      for the formals whose argument resolved to one unambiguous entry parameter
      (never for a struct member / array element of one). The origin alone says
      *a* parameter; addressing an ABI argument slot needs *which*. Threaded and
      re-walked exactly like ``param_bindings``, so two call sites forwarding
      different parameter positions disagree at the fold instead of one winning."""

    def __init__(
        self,
        bundle: _EngineBundle,
        state_vars_by_name: dict[str, Any],
        setters: set[str],
        alias_indeterminate: set[str],
        setter_scan_complete: bool,
        nested: bool,
        param_bindings: dict[str, tuple[str, ...]] | None = None,
        param_index_bindings: dict[str, int] | None = None,
    ) -> None:
        # Context-independent, shared across every entry that reaches this unit.
        self.engine = bundle.engine
        self.param_names = bundle.param_names
        self.merged = bundle.merged
        self.def_by_id = bundle.def_by_id
        self.param_indexes = bundle.param_indexes
        # Contract-level (constant within a contract) + the per-context nested flag.
        self.state_vars_by_name = state_vars_by_name
        self.setters = setters
        self.alias_indeterminate = alias_indeterminate
        self.setter_scan_complete = setter_scan_complete
        self.nested = nested
        self.param_bindings = param_bindings
        self.param_index_bindings = param_index_bindings


class _EngineBundle:
    """The context-independent provenance artifacts for one function: the SSA
    ``ProvenanceEngine`` (run to fixed point), formal-parameter base names, the
    Phi-merged local bases, and the SSA def-use index. All are pure functions of
    the function's own IR — identical whichever entry point reaches it — so the
    bundle is memoized per function across the whole build pass. Only the
    per-context ``nested`` interpretation lives on ``_UnitCtx``."""

    __slots__ = ("engine", "param_names", "merged", "def_by_id", "param_indexes")

    def __init__(
        self,
        engine: ProvenanceEngine,
        param_names: set[str],
        merged: set[str],
        def_by_id: dict[int, Any],
        param_indexes: dict[str, int],
    ) -> None:
        self.engine = engine
        self.param_names = param_names
        self.merged = merged
        self.def_by_id = def_by_id
        self.param_indexes = param_indexes


# Per-function memo of the context-independent bundle, keyed by the Slither
# function object (weak so it dies with the Slither instance). Collapses the
# prior O(entries × helpers) engine rebuilds to one run per function per pass.
_ENGINE_BUNDLE: WeakKeyDictionary[Any, _EngineBundle] = WeakKeyDictionary()


def _param_indexes_of(unit: Any) -> dict[str, int]:
    """``formal parameter base name -> positional index``. A name that repeats
    (shadowing, an unnamed formal reusing the empty name) is DROPPED: the index
    is used to address an ABI argument slot, so an ambiguous name must resolve to
    nothing rather than to the first match."""
    indexes: dict[str, int] = {}
    ambiguous: set[str] = set()
    for position, param in enumerate(getattr(unit, "parameters", []) or []):
        base = _base_name(getattr(param, "name", None))
        if not base:
            continue
        if base in indexes:
            ambiguous.add(base)
            continue
        indexes[base] = position
    for name in ambiguous:
        indexes.pop(name, None)
    return indexes


def _engine_bundle_for(unit: Any) -> _EngineBundle:
    cached = _ENGINE_BUNDLE.get(unit)
    if cached is not None:
        return cached
    from slither.core.cfg.node import NodeType  # type: ignore[import]
    from slither.core.variables.local_variable import LocalVariable  # type: ignore[import]
    from slither.slithir.operations import Phi  # type: ignore[import]

    engine = ProvenanceEngine(unit)
    engine.run()
    param_names = {
        base for param in getattr(unit, "parameters", []) or [] if (base := _base_name(getattr(param, "name", None)))
    }
    param_indexes = _param_indexes_of(unit)
    merged: set[str] = set()
    def_by_id: dict[int, Any] = {}
    for node in getattr(unit, "nodes", []) or []:
        # An ENTRYPOINT-node Phi is a parameter-binding phi (Slither's
        # interprocedural SSA linking a callee param to its caller argument), NOT
        # an intra-function cross-branch merge. Counting it as "merged" would
        # spuriously force every forwarded-param destination in an internal
        # helper to indeterminate. A genuine reassignment merge lives at an
        # ENDIF/other body node and is still caught.
        is_entrypoint = getattr(node, "type", None) == NodeType.ENTRYPOINT
        for ir in getattr(node, "irs_ssa", ()) or ():
            lvalue = getattr(ir, "lvalue", None)
            if lvalue is not None:
                def_by_id[id(lvalue)] = ir
            if isinstance(ir, Phi) and not is_entrypoint:
                nsv = getattr(lvalue, "non_ssa_version", None) or lvalue
                if isinstance(nsv, LocalVariable):
                    base = _base_name(getattr(lvalue, "name", None))
                    if base:
                        merged.add(base)
    bundle = _EngineBundle(engine, param_names, merged, def_by_id, param_indexes)
    try:
        _ENGINE_BUNDLE[unit] = bundle
    except TypeError:  # pragma: no cover — unit not weak-referenceable
        pass
    return bundle


def _build_unit_ctx(
    unit: Any,
    is_entry: bool,
    state_vars_by_name: dict[str, Any],
    setters: set[str],
    alias_indeterminate: set[str],
    setter_scan_complete: bool,
    param_bindings: dict[str, tuple[str, ...]] | None = None,
    param_index_bindings: dict[str, int] | None = None,
) -> _UnitCtx:
    return _UnitCtx(
        _engine_bundle_for(unit),
        state_vars_by_name,
        setters,
        alias_indeterminate,
        setter_scan_complete,
        not is_entry,
        param_bindings,
        param_index_bindings,
    )


def _ir_source_operands(ir: Any) -> list[Any]:
    """The value operands an IR derives its lvalue from — the edges of the
    def-use backward walk used by ``_reaches_merged_local``."""
    tn = type(ir).__name__
    if tn == "TypeConversion":
        return [getattr(ir, "variable", None)]
    if tn == "Assignment":
        return [getattr(ir, "rvalue", None)]
    if tn == "Phi":
        return list(getattr(ir, "rvalues", ()) or [])
    if tn == "Unpack":
        return [getattr(ir, "tuple", None) or getattr(ir, "rvalue", None)]
    if tn == "Unary":
        return [getattr(ir, "rvalue", None)]
    if tn == "Binary":
        return [getattr(ir, "variable_left", None), getattr(ir, "variable_right", None)]
    if tn == "Member":
        # ``s.field`` — the field access carries the base local's identity, so a
        # destination read off a branch-reassigned struct local must reach it.
        return [getattr(ir, "variable_left", None)]
    if tn == "Index":
        # ``arr[k]`` — both the base and the key select the element; a merge in
        # either makes the destination element ambiguous.
        return [getattr(ir, "variable_left", None), getattr(ir, "variable_right", None)]
    return []


def _reaches_merged_local(value: Any, ctx: _UnitCtx) -> bool:
    if value is None or not ctx.merged:
        return False
    seen: set[int] = set()
    stack: list[Any] = [value]
    while stack:
        v = stack.pop()
        if v is None or id(v) in seen:
            continue
        seen.add(id(v))
        if _base_name(getattr(v, "name", None)) in ctx.merged:
            return True
        ir = ctx.def_by_id.get(id(v))
        if ir is not None:
            stack.extend(_ir_source_operands(ir))
    return False


def _operand_is_direct(value: Any, param_names: set[str]) -> bool:
    """True when the operand is a definitive AST leaf (Tier-1 dispositive): a
    StateVariable, a Solidity built-in (``msg.sender``/``msg.value``), a literal
    constant, or a formal-parameter read with no intervening cast/computation.
    Temporaries/references (cast results, computed values) are Tier-2 traces."""
    if value is None:
        return False
    tn = type(value).__name__
    if "Temporary" in tn or "Reference" in tn or "Tuple" in tn:
        return False
    from slither.core.declarations.solidity_variables import SolidityVariable  # type: ignore[import]
    from slither.core.variables.state_variable import StateVariable  # type: ignore[import]
    from slither.slithir.variables import Constant  # type: ignore[import]

    if isinstance(value, (StateVariable, SolidityVariable, Constant)):
        return True
    if isinstance(getattr(value, "non_ssa_version", None), StateVariable):
        return True
    base = _base_name(getattr(value, "name", None))
    return bool(base) and base in param_names


def _state_var_target_kind(name: str, ctx: _UnitCtx) -> str:
    var = ctx.state_vars_by_name.get(name)
    if var is None:
        return "indeterminate"
    if getattr(var, "is_constant", False):
        return "constant"
    if getattr(var, "is_immutable", False):
        return "immutable"
    if name in ctx.setters:
        return "storage_setter"
    if name in ctx.alias_indeterminate:
        # Aliased into a callee we could not decide writes-through — the
        # no-setter proof for this specific var is unsound.
        return "indeterminate"
    # No attributed setter. Only a *complete* scan makes that a proven negative
    # ("fixed destination"); an assembly-sstore/delegatecall/unresolved-alias
    # blind spot leaves it unknown — never assert immutability we could not prove.
    return "storage_no_setter" if ctx.setter_scan_complete else "indeterminate"


# A ``neutral origin`` is the entry-rooted source of a value forwarded across an
# internal-call boundary, independent of whether the value is used as a
# destination or an amount. One of: ``("param",)`` (an entry parameter, the
# caller-directed origin), ``("msg_sender",)``, ``("caller_controlled",)``
# (tx.origin), ``("self",)`` (address(this)), ``("constant",)``,
# ``("state_variable", name)``, or ``("indeterminate",)``. ``_arg_origin``
# computes it for a call-site argument (chaining through the caller's own
# bindings); ``_origin_to_*_kind`` translates it back into the destination /
# amount lattice at the use site.


def _single_param_origin(source: Any, ctx: _UnitCtx) -> tuple[str, ...]:
    """The neutral origin one ``parameter`` source resolves to. On the entry its
    own parameter IS the caller-directed origin → ``("param",)``. In a nested
    callee look it up in the forwarded ``param_bindings``; a missing binding →
    ``("indeterminate",)``."""
    if not ctx.nested:
        return ("param",)
    if ctx.param_bindings is None:
        return ("indeterminate",)
    base = _base_name(source.parameter_name) if source.parameter_name else None
    return ctx.param_bindings.get(base, ("indeterminate",)) if base else ("indeterminate",)


def _source_neutral_origin(source: Any, ctx: _UnitCtx) -> tuple[str, ...]:
    """One provenance source → its neutral origin. A ``parameter`` chains through
    the entry-rooted binding (``_single_param_origin``); every other kind maps to
    a contract-global origin. Anything not a clean single origin (view/external
    call, block context, signature recovery) → ``("indeterminate",)``.

    This is what neutralizes Slither's entrypoint-Phi parameter binding: a nested
    forwarded param carries BOTH its own ``parameter`` seed AND the caller's
    argument source unioned in by the entry Phi. Resolving every source to a
    neutral origin and demanding they AGREE turns a consistent echo into that one
    origin, and any cross-site contamination into ``indeterminate``."""
    kind = source.kind
    if kind == "parameter":
        return _single_param_origin(source, ctx)
    if kind == "msg_sender":
        return ("msg_sender",)
    if kind == "tx_origin":
        # The transaction origin (an EOA the caller controls) — a proven
        # caller-directed destination, theft-shaped like msg_sender/param, but a
        # distinct address fact so it is not folded into msg_sender.
        return ("caller_controlled",)
    if kind == "self_address":
        return ("self",)
    if kind == "constant":
        # Carry the literal so a provably-zero value call can be recognized as a
        # non-flow. Classification only reads ``origin[0]`` so the extra element
        # is inert for the target/amount lattice.
        return ("constant", source.constant_value or "")
    if kind == "state_variable":
        return ("state_variable", source.state_variable_name) if source.state_variable_name else ("indeterminate",)
    # view_call, external_call, block_context, signature_recovery, top.
    return ("indeterminate",)


def _arg_origin(operand: Any, ctx: _UnitCtx) -> tuple[str, ...]:
    """The neutral origin a single call-site argument forwards, resolved in the
    caller's entry-rooted context. Every meaningful source resolves to a neutral
    origin and they must AGREE; any merge / unresolvable / multi-origin shape →
    ``("indeterminate",)`` — never a guessed member.

    A directly-read nested parameter takes the same entrypoint-Phi echo-drop the
    use-site classifiers take (``_forwarded_param_sources``): forwarding a
    parameter ONWARD through a second helper must resolve exactly as reading it
    at the send site would, or a two-hop forward through a helper that other
    entries also call (Lido ``claimWithdrawalsTo`` → ``_claim`` → ``_sendValue``,
    where ``_claim``'s Phi carries the sibling entries' ``msg.sender``) loses its
    binding to a phantom disagreement."""
    if operand is None:
        return ("indeterminate",)
    # An element read forwarded as an argument (``_execute(targets[i], …)``)
    # carries its ROOT base's origin — same rule, and same key-blindness, as
    # classifying it at a send site.
    elem = _element_origin(operand, ctx)
    if elem is not None:
        return elem
    if _reaches_merged_local(operand, ctx):
        return ("indeterminate",)
    call = _call_origin(operand, ctx)
    if call is not None:
        return call
    srcs = ctx.engine._sources_for_value(operand)
    if not srcs or is_top(srcs):
        return ("indeterminate",)
    forwarded = _forwarded_param_sources(srcs, ctx)
    if forwarded is not None:
        origins = {_single_param_origin(s, ctx) for s in forwarded}
    else:
        origins = {_source_neutral_origin(s, ctx) for s in srcs if s.kind != "computed"}
    if len(origins) == 1 and ("indeterminate",) not in origins:
        return next(iter(origins))
    return ("indeterminate",)


def _source_param_index(source: Any, ctx: _UnitCtx) -> int | None:
    """The ENTRY parameter index one provenance source resolves to — the
    positional twin of ``_single_param_origin``. ``None`` for every source that
    is not a parameter reaching one unambiguous entry parameter."""
    if source.kind != "parameter":
        return None
    base = _base_name(source.parameter_name) if source.parameter_name else None
    if not base:
        return None
    if not ctx.nested:
        return ctx.param_indexes.get(base)
    return ctx.param_index_bindings.get(base) if ctx.param_index_bindings else None


def _reads_element(operand: Any, ctx: _UnitCtx) -> bool:
    """True when the operand's value is read THROUGH an array/mapping/struct
    access (``a[k]``, ``s.field``, ``map[k].field``).

    Such a destination is not an ABI argument slot even when its root is a
    parameter: planting a probe address would mean rewriting a field inside an
    encoded struct/array. Index emission bails on this shape entirely — the
    ``target_kind`` (``param`` for a calldata-struct root, the base var's
    mutability for a storage root) is unaffected."""
    seen: set[int] = set()
    stack: list[Any] = [operand]
    while stack:
        v = stack.pop()
        if v is None or id(v) in seen:
            continue
        seen.add(id(v))
        ir = ctx.def_by_id.get(id(v))
        if ir is None:
            continue
        tn = type(ir).__name__
        if tn in ("Index", "Member"):
            return True
        if tn == "TypeConversion":
            stack.append(getattr(ir, "variable", None))
        elif tn == "Assignment":
            stack.append(getattr(ir, "rvalue", None))
    return False


def _operand_param_index(operand: Any, ctx: _UnitCtx) -> int | None:
    """The ENTRY parameter index an operand resolves to — the positional twin of
    ``_arg_origin``, and the ONLY producer of ``target_param_index``.

    Emits an index only when EVERY source the origin resolution considered is a
    parameter binding onto the SAME entry parameter, so the operand is that whole
    argument and nothing else. Element reads, merged locals, computed mixes,
    missing bindings and non-parameter origins all yield ``None`` — the caller
    must then plant no probe rather than address a guessed slot."""
    if operand is None or _reads_element(operand, ctx) or _reaches_merged_local(operand, ctx):
        return None
    srcs = ctx.engine._sources_for_value(operand)
    if not srcs or is_top(srcs):
        return None
    forwarded = _forwarded_param_sources(srcs, ctx)
    considered = forwarded if forwarded is not None else [s for s in srcs if s.kind != "computed"]
    if not considered:
        return None
    indexes = {_source_param_index(s, ctx) for s in considered}
    if len(indexes) != 1:
        return None
    return next(iter(indexes))


def _is_zero_literal(value: str) -> bool:
    try:
        return int(value, 0) == 0
    except (TypeError, ValueError):
        return False


def _amount_is_provably_zero(operand: Any, ctx: _UnitCtx) -> bool:
    """True when a value-call's ``call_value`` provably resolves to constant zero,
    threading the caller binding (OZ ``SafeERC20`` routes token transfers through
    ``Address.functionCallWithValue(token, data, 0)`` — a ``.call{value: value}``
    whose ``value`` param is bound to the literal ``0``). A zero-value call moves
    no ETH, so it is not a value-out flow and must not fold with a real send."""
    origin = _arg_origin(operand, ctx)
    return origin[0] == "constant" and len(origin) > 1 and _is_zero_literal(origin[1])


def _origin_to_target_kind(origin: tuple[str, ...], ctx: _UnitCtx) -> str:
    tag = origin[0]
    if tag == "param":
        return "param"
    if tag == "msg_sender":
        return "msg_sender"
    if tag == "caller_controlled":
        return "caller_controlled"
    if tag == "self":
        return "self"
    if tag == "constant":
        return "constant"
    if tag == "token_owner":
        return "token_owner"
    if tag == "state_variable":
        return _state_var_target_kind(origin[1], ctx)
    return "indeterminate"


def _is_derivation(computed_kind: str | None) -> bool:
    """True for a ``computed`` tag produced by arithmetic on other operands
    (``BinaryType.SUBTRACTION`` / ``UnaryType.*``) — as opposed to a tag that
    merely names the value read (``msg.value``, ``balance(address)``,
    ``member.<field>``)."""
    return computed_kind is not None and computed_kind.startswith(("BinaryType.", "UnaryType."))


def _is_subtraction(computed_kind: str | None) -> bool:
    """True for the one arithmetic op that makes a balance read a DELTA. A
    comparison (``Math.min``'s ``a < b``) or a scaling (``balance / 2``) is not a
    delta and must not borrow the name."""
    return computed_kind == "BinaryType.SUBTRACTION"


def _origin_to_amount_kind(origin: tuple[str, ...]) -> str:
    tag = origin[0]
    if tag == "param":
        return "param"
    if tag == "constant":
        return "fixed_constant"
    if tag == "state_variable":
        return "bounded_by_storage"
    # An address origin (msg.sender / tx.origin / self) forwarded as an amount is
    # not a meaningful value bound — stay indeterminate rather than invent one.
    return "indeterminate"


# Element-root origins we classify from. A storage root gives the base var's
# mutability, a parameter root gives ``param`` (an element of a caller-supplied
# array/struct is still caller-chosen), a constant root is fixed. Any other root
# (``address(this)`` — some solc versions lower ``address(this).balance`` to a
# Member — an unresolved local, a merged base) is NOT an element classification;
# the caller falls through to the source-set path instead.
_ELEMENT_ROOT_TAGS = ("param", "state_variable", "constant")

_ELEMENT_WALK_DEFS = ("TypeConversion", "Assignment", "Index", "Member")


def _element_root_origins(operand: Any, ctx: _UnitCtx) -> set[tuple[str, ...]] | None:
    """If ``operand`` reads an array/mapping/struct element (``a[k]`` /
    ``s.field`` / ``map[k].field``, possibly via a storage-pointer local
    ``Req storage rq = _requests[id]; rq.recipient``), the set of neutral origins
    of the access's ROOT base. ``None`` when it is not such an access.

    This is a POSITIVE structural test on the operand's def-use chain — an
    ``Index`` / ``Member`` op — so it distinguishes a genuine element read from
    the source-set-identical shape a forwarded param produces via the entrypoint
    Phi (which has no Index/Member IR). The KEY is deliberately ignored: every
    element of one base shares that base's origin, so the base alone decides the
    kind and a caller-chosen (or loop-merged) index cannot upgrade or degrade it."""
    from slither.core.variables.state_variable import StateVariable  # type: ignore[import]

    seen: set[int] = set()
    stack: list[Any] = [operand]
    origins: set[tuple[str, ...]] = set()
    found_access = False
    while stack:
        v = stack.pop()
        if v is None or id(v) in seen:
            continue
        seen.add(id(v))
        if isinstance(v, StateVariable) or isinstance(getattr(v, "non_ssa_version", None), StateVariable):
            # A bare state-var read only counts as an element base when it was
            # reached THROUGH an Index/Member (found_access) — a whole-var
            # destination stays a plain state_variable classification.
            continue
        ir = ctx.def_by_id.get(id(v))
        if ir is None:
            continue
        tn = type(ir).__name__
        if tn == "TypeConversion":
            stack.append(getattr(ir, "variable", None))
        elif tn == "Assignment":
            stack.append(getattr(ir, "rvalue", None))
        elif tn in ("Index", "Member"):
            found_access = True
            base = getattr(ir, "variable_left", None)
            base_nsv = getattr(base, "non_ssa_version", None)
            base_var = (
                base if isinstance(base, StateVariable) else base_nsv if isinstance(base_nsv, StateVariable) else None
            )
            if base_var is not None:
                if base_var.name:
                    origins.add(("state_variable", base_var.name))
            elif type(ctx.def_by_id.get(id(base))).__name__ in _ELEMENT_WALK_DEFS:
                # A nested access (map[k].field) or an aliasing local — keep
                # walking to the root rather than reading the intermediate
                # reference's base∪key source union.
                stack.append(base)
            else:
                # A parameter / merged / unresolvable root: resolve it exactly as
                # a forwarded call-site argument would be (binding-chained, with
                # the merged-local guard).
                origins.add(_arg_origin(base, ctx))
        # An unknown def (call return, etc.) ends this branch.
    return origins if (found_access and origins) else None


def _element_origin(operand: Any, ctx: _UnitCtx) -> tuple[str, ...] | None:
    """The neutral origin an element read takes from its ROOT base — NEVER from
    the caller-supplied key. ``None`` when the operand is not an element read, or
    when its root is not one we classify from (``address(this)``, a merged or
    unresolvable base). The caller then falls through to the source-set path,
    where the merged-local guard still applies — and that guard is also what
    catches a >1-root walk, since two roots require a Phi between them."""
    roots = _element_root_origins(operand, ctx)
    if roots is None or len(roots) != 1:
        return None
    root = next(iter(roots))
    return root if root[0] in _ELEMENT_ROOT_TAGS else None


# ERC-721 ``ownerOf(uint256)``. A destination read back from it is the CURRENT
# owner of the token id the caller passed: the caller chooses the id, the token's
# transfer history chooses the address. That is neither a caller-supplied
# argument (``param`` — the caller cannot name the payee) nor a fixed or
# admin-settable one (``storage_*`` — no setter redirects it), so it gets its own
# kind rather than being folded into a neighbour it would misdescribe.
_TOKEN_OWNER_SELECTOR = "0x6352211e"

# Def-chain edges that preserve "this value IS that call's return value".
_CALL_WALK_DEFS = ("TypeConversion", "Assignment")
_CALL_IR_OPS = ("InternalCall", "LibraryCall", "HighLevelCall")


def _call_standard_origin(ir: Any) -> tuple[str, ...]:
    """The neutral origin a recognized STANDARD callee returns. An unrecognized
    callee is ``("indeterminate",)`` — a return value we cannot name, NOT a value
    to keep resolving from the callee's internals."""
    if _selector_for(_callee_signature(ir)) == _TOKEN_OWNER_SELECTOR:
        return ("token_owner",)
    return ("indeterminate",)


def _call_origin(operand: Any, ctx: _UnitCtx) -> tuple[str, ...] | None:
    """The neutral origin of an operand that IS a call's return value. ``None``
    only when the operand does not resolve — through casts/copies alone — to
    exactly one call, in which case the caller falls through to the source set.

    A POSITIVE test on the def-use chain, not on the source set, for two reasons.
    A set-membership test would fire on a value merely TAINTED by the call
    (``ownerOf(id) ^ salt``) rather than one that IS its result. And going the
    other way, the source set of a DIRECTLY-READ nested parameter can carry a
    call tag as a Slither entrypoint-Phi echo from a sibling call site — blocking
    on that would degrade a perfectly resolvable forwarded parameter.

    Answering here is what keeps ``_forwarded_param_sources`` honest for call
    results. ``_handle_internal_call`` sets its lvalue to the callee's return
    sources UNIONED with the call tag, so ``ownerOf(id)`` carries
    ``{view_call, state_variable _owners, parameter id}`` — where the parameter
    is the mapping KEY, not the value. Falling through to the source set there
    lets the drop-the-rest shortcut pick ``param`` out of a real union and report
    a token-owner payout as a caller-chosen destination."""
    seen: set[int] = set()
    stack: list[Any] = [operand]
    origins: set[tuple[str, ...] | None] = set()
    while stack:
        v = stack.pop()
        if v is None or id(v) in seen:
            continue
        seen.add(id(v))
        ir = ctx.def_by_id.get(id(v))
        if ir is None:
            continue
        tn = type(ir).__name__
        if tn == "TypeConversion":
            stack.append(getattr(ir, "variable", None))
        elif tn == "Assignment":
            stack.append(getattr(ir, "rvalue", None))
        elif tn in _CALL_IR_OPS:
            origins.add(_call_standard_origin(ir))
    # Two calls reaching one operand require a Phi between them, so >1 origin is
    # a merge and must not resolve to either member.
    if len(origins) != 1:
        return ("indeterminate",) if origins else None
    return next(iter(origins))


def _element_kind(operand: Any, ctx: _UnitCtx, *, amount: bool) -> str | None:
    """An element read's destination/amount kind. A storage root yields the base
    var's mutability (``storage_setter`` / ``storage_no_setter`` /
    ``bounded_by_storage``) and can never become ``param``; a caller-supplied
    array/struct root yields ``param``."""
    origin = _element_origin(operand, ctx)
    if origin is None:
        return None
    return _origin_to_amount_kind(origin) if amount else _origin_to_target_kind(origin, ctx)


def _forwarded_param_sources(srcs: Any, ctx: _UnitCtx) -> list[Any] | None:
    """In a nested callee reached through a DIRECT forwarded read, the
    ``parameter`` sources whose bindings are the authoritative single-entry-path
    origin — or ``None`` when the drop-the-rest shortcut is not sound and the
    caller must use the all-sources-agree path instead.

    The other non-parameter sources present alongside a *directly-read* nested
    parameter can only be Slither entrypoint-Phi echoes (the parameter's
    interprocedural binding from OTHER call sites / entries) — a genuine in-body
    second origin needs a body Phi, already caught by ``_reaches_merged_local``.
    So for a direct read those echoes are safely dropped and the binding decides.

    But a ``computed`` operand (``Binary`` / ``Member`` / ``Unary`` / ``Length`` /
    ``SolidityCall`` attach a ``computed`` wrapper alongside ALL of their operand
    sources) can combine the forwarded parameter with a genuine co-origin and no
    Phi — ``dest = uint160(to) ^ uint160(owner)``. Dropping the co-origin there
    would guess the ``param`` member of a real union and make the nested
    classification MORE specific than the byte-identical entry-level code (which
    sees ``{parameter, state_variable}`` and yields indeterminate). So a computed
    operand returns ``None`` and falls through to the agreement path, where the
    disagreement correctly yields indeterminate while a computed-but-single-origin
    shape (a struct-member read of a forwarded param) still recovers.

    A CALL RESULT is the same trap without a ``computed`` wrapper to mark it, but
    it is intercepted upstream by ``_call_origin`` rather than here: the source
    set alone cannot tell a call the operand IS from a call tag echoed onto a
    forwarded parameter by a sibling call site."""
    if not ctx.nested:
        return None
    if any(s.kind == "computed" for s in srcs):
        return None
    params = [s for s in srcs if s.kind == "parameter"]
    return params or None


def _target_kind_from_sources(srcs: Any, ctx: _UnitCtx) -> str:
    if not srcs or is_top(srcs):
        return "indeterminate"
    # ``computed`` is a wrapper tag Binary/Member ops attach alongside the real
    # operand sources; it is never itself a destination origin. Every real source
    # resolves to a neutral origin (a nested forwarded ``parameter`` through its
    # binding); a single agreeing origin classifies, any MIX -> indeterminate.
    forwarded = _forwarded_param_sources(srcs, ctx)
    if forwarded is not None:
        kinds = {_origin_to_target_kind(_single_param_origin(s, ctx), ctx) for s in forwarded}
    else:
        kinds = {_origin_to_target_kind(_source_neutral_origin(s, ctx), ctx) for s in srcs if s.kind != "computed"}
    if len(kinds) == 1 and "indeterminate" not in kinds:
        return next(iter(kinds))
    return "indeterminate"


def _amount_kind_from_sources(srcs: Any, ctx: _UnitCtx) -> str:
    if not srcs or is_top(srcs):
        return "indeterminate"
    computed_kinds = {s.computed_kind for s in srcs if s.kind == "computed"}
    has_value = any(c == "msg.value" for c in computed_kinds)
    has_balance = any(c and "balance" in c for c in computed_kinds)
    if has_balance and not has_value and any(_is_derivation(c) for c in computed_kinds):
        # Arithmetic ON a balance read. Subtraction is a DELTA
        # (``address(this).balance - prevBalance``, ``balance - locked``) and gets
        # named; any other derivation (``balance / 2``) has no bound we can name.
        # Either way the OTHER operand must not win alone: reporting
        # ``balance - locked`` as ``bounded_by_storage``, or ``balance / 2`` as
        # ``fixed_constant``, credits that operand with bounding an amount that
        # actually tracks the balance. This runs ahead of the meaningful-source
        # split precisely because that operand is usually the only non-``computed``
        # source and would otherwise be the whole answer.
        return "balance_delta" if any(_is_subtraction(c) for c in computed_kinds) else "indeterminate"
    meaningful = {s.kind for s in srcs} - {"computed"}
    if not meaningful:
        # Pure computed: only ``msg.value`` and a bare ``address(this).balance``
        # read are unambiguous amount origins; hash/mixed tags stay indeterminate.
        if has_value and not has_balance:
            # A msg.value derivation (``msg.value - fee``) is still bounded by
            # what the caller attached to THIS call, so the label does not
            # over-claim the way a bare balance read would.
            return "msg_value"
        if has_balance and not has_value:
            # ``whole_balance`` asserts the send can drain everything the contract
            # holds — true only of a bare READ, and every derivation is gone by here.
            return "whole_balance"
        return "indeterminate"
    forwarded = _forwarded_param_sources(srcs, ctx)
    if forwarded is not None:
        kinds = {_origin_to_amount_kind(_single_param_origin(s, ctx)) for s in forwarded}
    else:
        kinds = {_origin_to_amount_kind(_source_neutral_origin(s, ctx)) for s in srcs if s.kind != "computed"}
    if len(kinds) == 1 and "indeterminate" not in kinds:
        return next(iter(kinds))
    return "indeterminate"


def _classify_site(operand: Any, ctx: _UnitCtx, *, amount: bool) -> tuple[str, str]:
    """Classify one destination/amount operand at one IR site -> (kind, tier).

    The load-bearing fallback: any operand that could be a collapsed
    cross-branch merge (``_reaches_merged_local``) is ``indeterminate`` — we
    never project a concrete kind the engine's base-name keying might have
    silently picked from an ambiguous set."""
    if operand is None:
        return ("indeterminate", "static_trace")
    # An array/mapping/struct element is classified by its ROOT base, detected
    # positively from the operand IR so it is not confused with a forwarded
    # parameter (source-set-identical via the entrypoint Phi). This runs BEFORE
    # the merged-local guard because the guard also walks the element KEY, and a
    # loop-merged index (``targets[i]``) says nothing about the destination's
    # kind — every element of the base shares its origin. A merged BASE is still
    # caught: the root resolves through ``_arg_origin``, which applies the guard.
    elem = _element_kind(operand, ctx, amount=amount)
    if elem is not None:
        return (elem, "static_trace")
    if _reaches_merged_local(operand, ctx):
        return ("indeterminate", "static_trace")
    # A recognized call's return value classifies from the callee's STANDARD
    # identity — a trace through the call, never a dispositive AST read.
    call = _call_origin(operand, ctx)
    if call is not None:
        kind = _origin_to_amount_kind(call) if amount else _origin_to_target_kind(call, ctx)
        return (kind, "static_trace")
    srcs = ctx.engine._sources_for_value(operand)
    kind = _amount_kind_from_sources(srcs, ctx) if amount else _target_kind_from_sources(srcs, ctx)
    if kind == "indeterminate":
        return ("indeterminate", "static_trace")
    # A ``parameter`` operand resolved inside a nested callee was recovered by
    # threading the caller's binding across the internal-call boundary — a trace,
    # not a dispositive AST fact at the entry. State-var / msg.sender reads are
    # contract-global and stay dispositive regardless of nesting.
    forwarded_param = ctx.nested and any(s.kind == "parameter" for s in srcs)
    direct = _operand_is_direct(operand, ctx.param_names) and not forwarded_param
    tier = "dispositive_ast" if direct else "static_trace"
    return (kind, tier)


def _fold_sites(sites: list[tuple[str, str]]) -> KindTier | None:
    """Collapse every contributing IR site's (kind, tier) to one classification.
    Sites must agree on a single non-indeterminate kind, else the union is
    ``indeterminate`` (the cross-site MIX rule). Tier is the weaker of the
    agreeing sites — one traced site makes the whole a ``static_trace``."""
    if not sites:
        return None
    kinds = {kind for kind, _ in sites}
    if "indeterminate" in kinds or len(kinds) != 1:
        return {"kind": "indeterminate", "tier": "static_trace"}
    tier = "static_trace" if any(t == "static_trace" for _, t in sites) else "dispositive_ast"
    return {"kind": next(iter(kinds)), "tier": tier}


# Re-walk insurance: bounds interprocedural recursion when a helper is reached
# with many distinct forwarded-binding signatures (a wide call DAG). Real helper
# chains are a handful of hops deep; a cutoff only drops sends past a depth no
# real destination reaches, in the safe direction (a missing flow, never a
# guessed one). The per-(unit, bindings) ``visited`` set already guarantees
# termination — this is belt-and-suspenders against pathological blow-up.
_VALUE_WALK_DEPTH_CAP = 128


def _bindings_for_call(ir: Any, callee: Any, ctx: _UnitCtx) -> tuple[dict[str, tuple[str, ...]], dict[str, int]]:
    """The param→neutral-origin map forwarded at one internal/library call site,
    resolved in the caller's ``ctx``, plus its param→entry-parameter-INDEX half.
    Each callee formal parameter binds to the entry-rooted origin of its
    positional argument (``_arg_origin``), chaining through the caller's own
    bindings so a multi-hop forward stays exact. The index map carries only the
    formals whose argument is one whole entry parameter."""
    bindings: dict[str, tuple[str, ...]] = {}
    index_bindings: dict[str, int] = {}
    args = list(getattr(ir, "arguments", []) or [])
    for param, arg in zip(getattr(callee, "parameters", []) or [], args):
        base = _base_name(getattr(param, "name", None))
        if not base:
            continue
        bindings[base] = _arg_origin(arg, ctx)
        index = _operand_param_index(arg, ctx)
        if index is not None:
            index_bindings[base] = index
    return bindings, index_bindings


def _value_flow_facts(function: Any) -> list[ValueFlow]:
    """Value movement facts, transitively. ``transferFrom`` whose ``from``
    is ``address(this)`` flows *out*; native ``transfer``/``send`` are value
    sinks Slither lowers to their own IR op (not a low-level call).

    Each flow additionally carries ``target_kind`` (where the funds go) and
    ``amount_kind`` (how much can leave), classified by reusing the SSA
    ``ProvenanceEngine`` per unit. Every IR site contributing to a flow is
    classified and the results are folded per flow key, so distinct
    destinations across branches/sites collapse to ``indeterminate`` instead of
    the first-seen winner."""
    flows: list[ValueFlow] = []
    seen: set[tuple[str, str | None, str, bool, str]] = set()
    # Keyed by (unit id, forwarded-binding signature): a helper reached with the
    # SAME bindings is deduped, but one reached with DIVERGENT bindings across
    # call sites is re-walked so the cross-site fold collapses to indeterminate.
    visited: set[tuple[int, Any, Any]] = set()
    target_sites: dict[tuple[str, str | None, str, bool, str], list[tuple[str, str]]] = {}
    amount_sites: dict[tuple[str, str | None, str, bool, str], list[tuple[str, str]]] = {}
    target_indexes: dict[tuple[str, str | None, str, bool, str], list[int | None]] = {}

    contract = getattr(function, "contract", None)
    state_vars_by_name: dict[str, Any] = {
        getattr(v, "name", "") or "": v for v in (_all_state_variables(contract) if contract is not None else [])
    }
    setters = _setter_state_vars(contract) if contract is not None else set()
    alias_indeterminate = _aliased_storage_writes(contract)[1] if contract is not None else set()
    scan_complete = _setter_scan_complete(contract) if contract is not None else False

    def unit_ctx(
        unit: Any,
        is_entry: bool,
        param_bindings: dict[str, tuple[str, ...]] | None,
        param_index_bindings: dict[str, int] | None,
    ) -> _UnitCtx:
        # Fresh per (unit, bindings); the expensive per-unit ProvenanceEngine is
        # memoized inside ``_engine_bundle_for``, so this wrapper is cheap.
        return _build_unit_ctx(
            unit,
            is_entry,
            state_vars_by_name,
            setters,
            alias_indeterminate,
            scan_complete,
            param_bindings,
            param_index_bindings,
        )

    def add(flow: ValueFlow, target: Any, amount: Any, ctx: _UnitCtx) -> None:
        key = (flow["kind"], flow["selector"], flow["direction"], flow["from_is_self"], flow["origin"])
        target_sites.setdefault(key, []).append(_classify_site(target, ctx, amount=False))
        amount_sites.setdefault(key, []).append(_classify_site(amount, ctx, amount=True))
        target_indexes.setdefault(key, []).append(_operand_param_index(target, ctx))
        if key in seen:
            return
        seen.add(key)
        flows.append(flow)

    def walk(
        unit: Any,
        origin: str,
        is_entry: bool,
        param_bindings: dict[str, tuple[str, ...]] | None,
        param_index_bindings: dict[str, int] | None,
        depth: int,
    ) -> None:
        sig = None if param_bindings is None else frozenset(param_bindings.items())
        # The index half is part of the identity: two sites can forward the same
        # origins from DIFFERENT parameter positions, and deduping those would
        # let the first-walked site's index stand for both.
        index_sig = None if param_index_bindings is None else frozenset(param_index_bindings.items())
        key = (id(unit), sig, index_sig)
        if key in visited or depth > _VALUE_WALK_DEPTH_CAP:
            return
        visited.add(key)
        ctx: _UnitCtx | None = None  # built lazily only if the unit moves value or forwards args

        this_ids: set[int] = set()
        this_names: set[str] = set()
        for node in getattr(unit, "nodes", []) or []:
            for ir in getattr(node, "irs_ssa", ()) or ():
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
            for ir in getattr(node, "irs_ssa", ()) or ():
                op = type(ir).__name__
                if op in ("Transfer", "Send"):
                    if ctx is None:
                        ctx = unit_ctx(unit, is_entry, param_bindings, param_index_bindings)
                    add(
                        {
                            "kind": "native_transfer_send",
                            "selector": None,
                            "direction": "out",
                            "from_is_self": True,
                            "origin": origin,
                        },
                        getattr(ir, "destination", None),
                        getattr(ir, "call_value", None),
                        ctx,
                    )
                elif op == "HighLevelCall":
                    selector = _selector_for(_callee_signature(ir))
                    arguments = list(getattr(ir, "arguments", []) or [])
                    if selector in _ERC20_PULL_SELECTORS:
                        from_arg = arguments[0] if arguments else None
                        from_self = _arg_is_address_this(from_arg, this_ids, this_names)
                        if ctx is None:
                            ctx = unit_ctx(unit, is_entry, param_bindings, param_index_bindings)
                        add(
                            {
                                "kind": "callee_erc20_selector",
                                "selector": selector,
                                "direction": "out" if from_self else "in",
                                "from_is_self": from_self,
                                "origin": origin,
                            },
                            arguments[1] if len(arguments) > 1 else None,  # to
                            arguments[2] if len(arguments) > 2 else None,  # amount
                            ctx,
                        )
                    elif selector in _ERC20_SEND_SELECTORS:
                        if ctx is None:
                            ctx = unit_ctx(unit, is_entry, param_bindings, param_index_bindings)
                        add(
                            {
                                "kind": "callee_erc20_selector",
                                "selector": selector,
                                "direction": "out",
                                "from_is_self": True,
                                "origin": origin,
                            },
                            arguments[0] if arguments else None,  # to
                            arguments[1] if len(arguments) > 1 else None,  # amount
                            ctx,
                        )
                elif op == "LowLevelCall" and "value:" in str(ir):
                    if ctx is None:
                        ctx = unit_ctx(unit, is_entry, param_bindings, param_index_bindings)
                    call_value = getattr(ir, "call_value", None)
                    # A provably-zero value call (OZ SafeERC20's
                    # ``functionCallWithValue(token, data, 0)``) moves no ETH — not
                    # a value-out flow, and must not fold with a real send on the
                    # same function's flow key.
                    if not _amount_is_provably_zero(call_value, ctx):
                        add(
                            {
                                "kind": "low_level_value_call",
                                "selector": None,
                                "direction": "out",
                                "from_is_self": True,
                                "origin": origin,
                            },
                            getattr(ir, "destination", None),
                            call_value,
                            ctx,
                        )
                if op in ("InternalCall", "LibraryCall"):
                    callee = getattr(ir, "function", None)
                    if callee is not None and getattr(callee, "nodes", None):
                        child_origin = "guard" if (origin == "guard" or _is_modifier_call(ir)) else "body"
                        if ctx is None:
                            ctx = unit_ctx(unit, is_entry, param_bindings, param_index_bindings)
                        child_bindings, child_index_bindings = _bindings_for_call(ir, callee, ctx)
                        walk(callee, child_origin, False, child_bindings, child_index_bindings, depth + 1)

    walk(function, "body", True, None, None, 0)
    for flow in flows:
        key = (flow["kind"], flow["selector"], flow["direction"], flow["from_is_self"], flow["origin"])
        target = _fold_sites(target_sites.get(key, []))
        amount = _fold_sites(amount_sites.get(key, []))
        if target is not None:
            flow["target_kind"] = target
            index = _fold_param_index(target, target_indexes.get(key, []))
            if index is not None:
                flow["target_param_index"] = index
        if amount is not None:
            flow["amount_kind"] = amount
    return flows


def _fold_param_index(target: KindTier, indexes: list[int | None]) -> int | None:
    """The one entry-parameter slot every contributing site sent funds to.

    Requires the folded kind to BE ``param`` (so the destination is an entry
    parameter at all) and every site to have resolved the same index. A site that
    resolved none, or two sites resolving different positions, yields ``None``:
    the flow is still a ``param`` destination, we just cannot say which slot."""
    if target["kind"] != "param" or not indexes:
        return None
    distinct = set(indexes)
    if len(distinct) != 1:
        return None
    return next(iter(distinct))


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

    artifact: EffectsArtifact = {
        "schema_version": SCHEMA_VERSION,
        "contract_name": getattr(contract, "name", None),
        "functions": functions,
    }
    token_slots = derive_token_slots(contract)
    if token_slots is not None:
        artifact["token_slots"] = cast("TokenSlots", token_slots)
    return artifact
