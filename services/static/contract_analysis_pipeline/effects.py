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
"""

from __future__ import annotations

from typing import Any, TypedDict

from eth_utils.crypto import keccak

from .summaries import (
    _action_summary,
    _effect_labels,
)

SCHEMA_VERSION = "semantic"


class SinkRecord(TypedDict):
    """One sink reachable from a given external function. ``id`` is a
    stable cross-reference; ``function`` is the *originating* external
    function (the entry-point), not the unit where the IR lives — that
    way consumers can group sinks by entry without re-walking
    internal calls."""

    id: str
    function: str
    kind: str  # state_write | external_call | delegatecall | contract_creation | selfdestruct
    target: str
    selector: str | None


class EffectInfo(TypedDict):
    function: str
    selector: str
    abi_signature: str
    sinks: list[SinkRecord]
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
) -> list[tuple[str, str, str | None]]:
    """Recursively gather sink triples from ``unit`` and any
    internal/library callees. Returns a flat list (de-dup happens at
    the caller level so we can keep distinct indices)."""
    unit_key = getattr(unit, "canonical_name", None) or getattr(unit, "full_name", None) or id(unit)
    if unit_key in visited:
        return []
    visited.add(unit_key)

    found: list[tuple[str, str, str | None]] = []
    for node in getattr(unit, "nodes", []) or []:
        for var_name in _node_kind_state_writes(node):
            found.append(("state_write", var_name, None))
        found.extend(_classify_node_irs(node))
        # Recurse into internal/library callees so transitive writes
        # surface on the entry-point's record.
        for ir in _node_irs(node):
            op = type(ir).__name__
            if op not in ("InternalCall", "LibraryCall"):
                continue
            callee = getattr(ir, "function", None)
            if callee is None or not getattr(callee, "nodes", None):
                continue
            found.extend(_walk_unit_for_sinks(callee, visited))
    return found


def _build_sink_records(function: Any) -> list[SinkRecord]:
    """One sink per (kind, target) pair we discover, transitively
    deduped while preserving order. The selector field on
    ``SinkRecord`` is per-sink, not per-function: only ``external_call``
    sinks carry one, and only when Slither exposes the called function's
    canonical signature."""
    function_name = _function_full_name(function)
    triples = _walk_unit_for_sinks(function, set())

    out: list[SinkRecord] = []
    seen: set[tuple[str, str, str | None]] = set()
    for kind, target, selector in triples:
        key = (kind, target, selector)
        if key in seen:
            continue
        seen.add(key)
        idx = len(out)
        record: SinkRecord = {
            "id": _sink_id(function_name, kind, target, idx),
            "function": function_name,
            "kind": kind,
            "target": target,
            "selector": selector,
        }
        out.append(record)
    return out


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


def _effect_info_for_function(function: Any) -> EffectInfo:
    sinks = _build_sink_records(function)
    effects: list[str] = []

    # ``effect_targets`` remains a compatibility display field. Semantic
    # consumers should read ``sinks`` and selectors instead.
    effect_targets = _effect_targets_from_sinks(sinks)

    # _effect_labels takes a synthetic graph-entry analog so its
    # ``sink_kinds`` layer still triggers (delegatecall_execution,
    # selfdestruct_capability, contract_deployment).
    sink_kinds = sorted({s["kind"] for s in sinks})
    effect_context = {
        "effects": list(effects),
        "effect_targets": list(effect_targets),
        "sink_kinds": sink_kinds,
        "sinks": list(sinks),
    }
    labels = _effect_labels(function, effect_context)
    # Functions with external_call sinks but no specific (mint/burn/asset/etc)
    # label get ``external_contract_call`` directly from the sink shape.
    has_external_call = any(s["kind"] == "external_call" for s in sinks)
    if has_external_call and not any(
        lbl
        in (
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
        )
        for lbl in labels
    ):
        labels.append("external_contract_call")
    summary = _action_summary(labels, list(effect_targets))

    signature = _function_full_name(function)
    selector = _selector_for(signature) or ""
    return {
        "function": signature,
        "selector": selector,
        "abi_signature": signature,
        "sinks": sinks,
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


def build_effects(contract: Any) -> EffectsArtifact:
    """Return the ``effects`` artifact for ``contract``: one
    ``EffectInfo`` per externally-observable function (external,
    public, fallback, receive)."""
    functions: dict[str, EffectInfo] = {}
    for fn in getattr(contract, "functions", []) or []:
        if not _is_externally_observable(fn):
            continue
        info = _effect_info_for_function(fn)
        functions[info["function"]] = info

    return {
        "schema_version": SCHEMA_VERSION,
        "contract_name": getattr(contract, "name", None),
        "functions": functions,
    }


# ---------------------------------------------------------------------------
# Cross-function ownership post-pass.
#
# ``transferOwnership`` looks like a plain address setter until you know
# ``owner`` is the var its gate compares to the caller. The predicate pipeline
# already resolves that — through the ``owner()`` / ``_checkOwner`` getter
# chain — into a ``caller_authority`` *equality* leaf naming the exact scalar.
# This pass reads those leaves and tags the functions that write the scalar:
# precise (an incidental ``require(config != 0)`` read is a ``business`` leaf,
# never ``caller_authority``) and name-agnostic.
#
# Only the scalar-equality (ownership) shape is harvested. Role *membership*
# maps are matched by selector instead (summaries._ACCESS_CONTROL_SELECTORS):
# a caller-keyed data map (e.g. LayerZero ``composeQueue``) is structurally a
# caller_authority membership leaf too, so writing one is not reliably "role
# management".
# ---------------------------------------------------------------------------

# The coarse fallbacks a precise ownership label supersedes on the same fn.
_COARSE_AUTHORITY_LABELS = ("hook_update", "external_contract_call")


def _iter_predicate_leaves(tree: Any) -> Any:
    """Yield every leaf dict in a predicate tree (op/LEAF/children shape)."""
    if not isinstance(tree, dict):
        return
    if tree.get("op") == "LEAF":
        leaf = tree.get("leaf")
        if isinstance(leaf, dict):
            yield leaf
        return
    for child in tree.get("children") or []:
        yield from _iter_predicate_leaves(child)


def _owner_vars_from_predicate_trees(predicate_trees_artifact: Any) -> set[str]:
    """State-var names that a ``caller_authority`` *equality* leaf compares to
    the caller (``owner == msg.sender``), across every function's predicate
    tree — i.e. the scalar owner/admin pointers."""
    trees = predicate_trees_artifact.get("trees") if isinstance(predicate_trees_artifact, dict) else None
    if not isinstance(trees, dict):
        return set()
    owner_vars: set[str] = set()
    for tree in trees.values():
        for leaf in _iter_predicate_leaves(tree):
            if leaf.get("authority_role") != "caller_authority":
                continue
            if leaf.get("kind") == "equality" and leaf.get("references_msg_sender"):
                for operand in leaf.get("operands") or []:
                    name = operand.get("state_variable_name") if isinstance(operand, dict) else None
                    if name:
                        owner_vars.add(name)
    return owner_vars


def apply_authority_effect_labels(
    contract: Any,
    effects_artifact: Any,
    predicate_trees_artifact: Any,
) -> None:
    """Tag a function ``ownership_transfer`` when it writes a scalar the
    predicate trees identify as the caller-authorizing var (an owner/admin
    pointer). Supersedes the coarse ``hook_update`` / ``external_contract_call``
    fallbacks on that function and refreshes its action summary. Mutates
    ``effects_artifact`` in place; a no-op if either artifact errored."""
    functions = effects_artifact.get("functions") if isinstance(effects_artifact, dict) else None
    if not isinstance(functions, dict):
        return
    owner_vars = _owner_vars_from_predicate_trees(predicate_trees_artifact)
    if not owner_vars:
        return
    for fn in getattr(contract, "functions", []) or []:
        info = functions.get(_function_full_name(fn))
        if not isinstance(info, dict):
            continue
        written = {getattr(var, "name", None) for var in fn.all_state_variables_written()}
        if "ownership_transfer" in (info.get("effect_labels") or []) or not (written & owner_vars):
            continue
        labels = [label for label in (info.get("effect_labels") or []) if label not in _COARSE_AUTHORITY_LABELS]
        labels.append("ownership_transfer")
        info["effect_labels"] = labels
        info["action_summary"] = _action_summary(labels, list(info.get("effect_targets") or []))
