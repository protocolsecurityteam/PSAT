"""Build the semantic predicate-tree artifact for a contract.

Runs the full predicate pipeline (``build_predicate_tree`` per
function + ``apply_writer_gate_pass`` + ``apply_reentrancy_pause_pass``
across the contract) and returns a JSON-ready dict keyed on each
externally-callable function's full name.

The artifact is emitted as the static stage's guard carrier. The
separate ``effects`` artifact carries sink/effect data for every
externally-observable function.

Convention:
  * present + tree → function is guarded by the tree's predicate.
  * absent → function is unguarded (publicly callable). The
    resolver maps unguarded to ``CapabilityExpr.public`` /
    ``conditional_universal`` per its own rules.

External/public visibility is the boundary we report on — internal/
private functions never appear in the output. We also skip
constructors and fallback/receive functions (their guard semantics
are different from ordinary external entry points).
"""

from __future__ import annotations

import logging
import os
import time
from collections.abc import Callable
from typing import Any

from eth_utils.crypto import keccak

from .internal_authority_slot import apply_internal_authority_slot_pass
from .mapping_events import WriterEventSpec, discover_mapping_writer_events
from .predicate_types import PredicateTree
from .predicates import _helper_engine_cache, build_predicate_tree, build_return_predicate_tree
from .reentrancy_pause import PauseInfo, apply_reentrancy_pause_pass
from .writer_gate import apply_writer_gate_pass

logger = logging.getLogger(__name__)

SCHEMA_VERSION = "semantic"


def _slow_function_threshold_ms() -> int:
    """Per-function log threshold for the predicate-builder profiler.

    Functions whose ``build_predicate_tree`` + ``build_return_predicate_tree``
    cost more than this are surfaced as ``predicate_function_slow`` lines
    so a Loki ``top by (function)`` query identifies the per-contract
    hot spots without needing the aggregate JSON.

    Env: ``PSAT_PREDICATE_FUNCTION_SLOW_MS`` (default 250).
    """
    try:
        return max(0, int(os.getenv("PSAT_PREDICATE_FUNCTION_SLOW_MS", "250")))
    except ValueError:
        return 250


def _predicate_summary_threshold_ms() -> int:
    """Aggregate threshold below which the per-contract predicate summary
    is suppressed. Cheap contracts don't need a line each.

    Env: ``PSAT_PREDICATE_SUMMARY_MS`` (default 500).
    """
    try:
        return max(0, int(os.getenv("PSAT_PREDICATE_SUMMARY_MS", "500")))
    except ValueError:
        return 500


def _empty_pause_info() -> PauseInfo:
    return {
        "pause_state_vars": [],
        "pause_toggle_functions": [],
        "reentrancy_state_vars": [],
        "reentrancy_guarded_functions": [],
    }


_EMPTY_PAUSE_INFO: PauseInfo = {
    "pause_state_vars": [],
    "pause_toggle_functions": [],
    "reentrancy_state_vars": [],
    "reentrancy_guarded_functions": [],
}


def _canonical_signature(fn: Any) -> str | None:
    """Slither's EVM-canonical ABI signature for ``fn`` — contract/interface
    params lowered to ``address``, enums to ``uint8``, structs to their tuple
    form — or ``None`` when Slither can't lower it.

    The trees here are keyed on Slither ``full_name``, which keeps user-defined
    parameter type names (``addAsset(ERC20)``,
    ``executeTasks(IEtherFiOracle.OracleReport)``). The real EVM selector can't
    be recovered from that string downstream: a struct's field layout and an
    enum's ``uint8`` width are already gone, and the name alone can't tell a
    struct/enum apart from a contract. ``solidity_signature`` still has the type
    objects and lowers them correctly, so we capture it here while Slither is
    live. It raises for the occasional non-lowerable (e.g. recursive) struct
    param; those drop out and consumers fall back to the string-level
    normalization (the prior, contract-only-correct behavior)."""
    try:
        signature = fn.solidity_signature
    except (ValueError, AttributeError, KeyError, TypeError):
        return None
    if isinstance(signature, str) and "(" in signature and signature.endswith(")"):
        return signature
    return None


def build_predicate_artifacts(contract: Any) -> dict[str, Any]:
    """Return a JSON-serializable dict of predicate trees for every
    external/public function on ``contract``.

    Functions whose tree is ``None`` (no revert paths) are omitted
    from the output. The resolver treats absent entries as
    unguarded.
    """
    artifact, _ = build_predicate_artifacts_with_pause_info(contract)
    return artifact


def build_predicate_artifacts_with_pause_info(
    contract: Any,
) -> tuple[dict[str, Any], PauseInfo]:
    """Build the predicate artifact and return the structured
    ``PauseInfo`` from ``apply_reentrancy_pause_pass``. The pipeline
    consumes the pause info to drive ``_detect_pausability``.

    Emits per-function and per-pass timing logs so the next live run
    can pinpoint whether the predicate stage's cost is concentrated in
    a handful of expensive functions or spread evenly across many.
    Functions slower than ``_slow_function_threshold_ms()`` log their
    own line; the aggregate summary fires when the whole per-contract
    cost exceeds ``_predicate_summary_threshold_ms()``.
    """
    contract_name = getattr(contract, "name", None)
    per_function_ms: list[tuple[str, int]] = []
    slow_threshold_ms = _slow_function_threshold_ms()
    pass_durations_ms: dict[str, int] = {}

    started = time.monotonic()
    # Scope a per-contract helper-engine cache for the cross-fn
    # build path. Multiple functions on the same contract often share
    # helper guards; this cache makes later cross-fn builds effectively
    # free.
    cache_token = _helper_engine_cache.set({})
    try:
        trees: dict[str, PredicateTree] = {}
        check_trees: dict[str, PredicateTree] = {}
        # full_name -> EVM-canonical ABI signature, for every entry point whose
        # canonical form differs from full_name (i.e. it has a contract/enum/
        # struct param). Lets the selector consumers key on the true ``msg.sig``
        # instead of re-deriving it from the lossy full_name string.
        canonical_signatures: dict[str, str] = {}
        # ``functions_entry_points`` is the deduped surface: for an
        # overridden virtual function (every OZ AccessControl method on a
        # contract that inherits it), Slither's ``functions`` returns
        # *both* the shadowed base ``Function`` object and the override
        # — same ``full_name``, different ``id`` — and the predicate
        # builder used to run to completion on both, with only the
        # last-write-wins write to ``trees[full_name]`` surviving.
        # On CumulativeMerkleDrop that wasted ~146 s per contract
        # (grantRole base = 69 s + revokeRole base = 77 s, both
        # discarded). Entry points are the API surface we report on
        # anyway, so this is the right iteration target.
        for fn in getattr(contract, "functions_entry_points", []) or []:
            if not _is_externally_callable(fn):
                continue
            canonical = _canonical_signature(fn)
            if canonical is not None and canonical != fn.full_name:
                canonical_signatures[fn.full_name] = canonical
            fn_started = time.monotonic()
            tree = build_predicate_tree(fn)
            if tree is not None:
                trees[fn.full_name] = tree
            check_tree = build_return_predicate_tree(fn)
            if check_tree is not None:
                check_trees[fn.full_name] = check_tree
            fn_ms = int((time.monotonic() - fn_started) * 1000)
            per_function_ms.append((fn.full_name, fn_ms))
            if fn_ms >= slow_threshold_ms:
                logger.info(
                    "predicate function %s on %s took %dms",
                    fn.full_name,
                    contract_name or "<unknown>",
                    fn_ms,
                    extra={
                        "phase": "predicate_function_slow",
                        "duration_ms": fn_ms,
                        "function": fn.full_name,
                        "contract_name": contract_name,
                        "profile_kind": "predicate_function_slow",
                    },
                )
    finally:
        _helper_engine_cache.reset(cache_token)
    per_function_total_ms = int((time.monotonic() - started) * 1000)

    pause_info = _empty_pause_info()
    # Cross-contract passes mutate trees in place: writer-gate's
    # writer-side analysis can promote 1-key membership leaves to
    # caller_authority once it sees the full set of writers, and
    # reentrancy/pause analyzers cross-reference state-vars across
    # the contract's functions.
    all_trees: dict[str, PredicateTree] = dict(trees)
    check_tree_keys: dict[str, str] = {}
    for sig, tree in check_trees.items():
        key = sig if sig not in all_trees else f"check:{sig}"
        all_trees[key] = tree
        check_tree_keys[sig] = key
    if all_trees:
        pass_started = time.monotonic()
        apply_writer_gate_pass(contract, all_trees)
        pass_durations_ms["writer_gate"] = int((time.monotonic() - pass_started) * 1000)

        pass_started = time.monotonic()
        apply_mapping_event_hint_pass(contract, all_trees)
        pass_durations_ms["mapping_event_hints"] = int((time.monotonic() - pass_started) * 1000)

        pass_started = time.monotonic()
        apply_solmate_authority_hint_pass(contract, all_trees)
        pass_durations_ms["solmate_authority_hints"] = int((time.monotonic() - pass_started) * 1000)

        pass_started = time.monotonic()
        apply_internal_authority_slot_pass(contract, all_trees)
        pass_durations_ms["internal_authority_slot"] = int((time.monotonic() - pass_started) * 1000)

        pass_started = time.monotonic()
        pause_info = apply_reentrancy_pause_pass(contract, all_trees)
        pass_durations_ms["reentrancy_pause"] = int((time.monotonic() - pass_started) * 1000)

        trees = {sig: all_trees[sig] for sig in trees}
        check_trees = {sig: all_trees[check_tree_keys[sig]] for sig in check_trees}

    artifact = {
        "schema_version": SCHEMA_VERSION,
        "contract_name": contract_name,
        "trees": trees,
    }
    if canonical_signatures:
        artifact["canonical_signatures"] = canonical_signatures
    if check_trees:
        artifact["check_trees"] = check_trees

    total_ms = int((time.monotonic() - started) * 1000)
    if total_ms >= _predicate_summary_threshold_ms():
        # Top 5 slowest functions so a Loki query can rank "which
        # functions burn predicate-builder budget" without parsing the
        # full distribution.
        top_slow = sorted(per_function_ms, key=lambda kv: kv[1], reverse=True)[:5]
        logger.info(
            "predicate summary for %s: total=%dms fns=%d per_fn=%dms passes=%s",
            contract_name or "<unknown>",
            total_ms,
            len(per_function_ms),
            per_function_total_ms,
            pass_durations_ms,
            extra={
                "phase": "predicate_summary",
                "duration_ms": total_ms,
                "per_function_total_ms": per_function_total_ms,
                "function_count": len(per_function_ms),
                "pass_durations_ms": pass_durations_ms,
                "top_slow_functions": [{"function": name, "duration_ms": ms} for name, ms in top_slow],
                "contract_name": contract_name,
                "profile_kind": "predicate_summary",
            },
        )

    return artifact, pause_info


def apply_mapping_event_hint_pass(contract: Any, trees: dict[str, PredicateTree]) -> None:
    """Attach generic mapping-writer event hints to matching leaves.

    ``discover_mapping_writer_events`` already finds semantic writer
    evidence like ``wards[user] = 1; emit Rely(user)`` or
    ``roles[user] = mask; emit RolesUpdated(user, mask)``. This pass
    copies that evidence onto matching ``mapping_membership`` descriptors.
    """
    specs_by_mapping: dict[str, list[WriterEventSpec]] = {}
    for spec in discover_mapping_writer_events(contract):
        mapping_name = spec.get("mapping_name")
        if mapping_name:
            specs_by_mapping.setdefault(mapping_name, []).append(spec)

    if not specs_by_mapping:
        return

    for tree in trees.values():
        _walk_tree_leaves(tree, lambda leaf: _attach_hints_to_leaf(leaf, specs_by_mapping))


# Solmate ``Auth``/``RolesAuthority``: ``requiresAuth`` authorizes via
# ``authority.canCall(msg.sender, address(this), msg.sig)``. The static stage
# already emits this as an ``external_set`` leaf carrying ``authority_contract``
# but no events. Attach the RolesAuthority role-event topics so the event-log
# indexer enrolls them (the event address resolves from ``authority_contract``
# at index time); the Solmate adapter then reconstructs the caller set. canCall
# is a two-event join (capability ⋈ user-role), so the generic mapping-event
# path can't cover it.
_SOLMATE_CANCALL_SIGNATURE = "canCall(address,address,bytes4)"
_SOLMATE_ROLE_EVENT_SIGNATURES = (
    "RoleCapabilityUpdated(uint8,address,bytes4,bool)",
    "PublicCapabilityUpdated(address,bytes4,bool)",
    "UserRoleUpdated(address,uint8,bool)",
)


def apply_solmate_authority_hint_pass(contract: Any, trees: dict[str, PredicateTree]) -> None:
    del contract
    cancall_selector = "0x" + keccak(text=_SOLMATE_CANCALL_SIGNATURE).hex()[:8]
    role_topics = ["0x" + keccak(text=signature).hex() for signature in _SOLMATE_ROLE_EVENT_SIGNATURES]

    def attach(leaf: dict[str, Any]) -> None:
        descriptor = leaf.get("set_descriptor")
        if not isinstance(descriptor, dict) or descriptor.get("kind") != "external_set":
            return
        signature = descriptor.get("callee_signature")
        selector = descriptor.get("callee_selector")
        is_cancall = (isinstance(signature, str) and signature.replace(" ", "") == _SOLMATE_CANCALL_SIGNATURE) or (
            isinstance(selector, str) and selector.lower() == cancall_selector
        )
        if not is_cancall:
            return
        hints = list(descriptor.get("enumeration_hint") or [])
        existing = {h.get("topic0") for h in hints if isinstance(h, dict)}
        for topic0 in role_topics:
            if topic0 in existing:
                continue
            hints.append(
                {
                    "event_address": None,
                    "topic0": topic0,
                    "topics_to_keys": {},
                    "data_to_keys": {},
                    "direction": "set",
                }
            )
        if hints:
            descriptor["enumeration_hint"] = hints

    for tree in trees.values():
        _walk_tree_leaves(tree, attach)


def _walk_tree_leaves(node: Any, callback: Callable[[dict[str, Any]], None]) -> None:
    if not isinstance(node, dict):
        return
    if node.get("op") == "LEAF":
        leaf = node.get("leaf")
        if isinstance(leaf, dict):
            callback(leaf)
        return
    for child in node.get("children") or []:
        _walk_tree_leaves(child, callback)


def _attach_hints_to_leaf(leaf: dict[str, Any], specs_by_mapping: dict[str, list[WriterEventSpec]]) -> None:
    descriptor = leaf.get("set_descriptor")
    if not isinstance(descriptor, dict) or descriptor.get("kind") != "mapping_membership":
        return
    storage_var = descriptor.get("storage_var")
    if not isinstance(storage_var, str) or not storage_var:
        return
    specs = specs_by_mapping.get(storage_var)
    if not specs:
        return
    member_key_index = _caller_key_index(descriptor.get("key_sources") or [])
    if member_key_index is None:
        return

    hints = list(descriptor.get("enumeration_hint") or [])
    seen = {_hint_identity(h) for h in hints if isinstance(h, dict)}
    for spec in specs:
        hint = _event_hint_from_writer_spec(spec, member_key_index)
        identity = _hint_identity(hint)
        if identity in seen:
            continue
        seen.add(identity)
        hints.append(hint)
    if hints:
        descriptor["enumeration_hint"] = hints


def _caller_key_index(key_sources: list[dict[str, Any]]) -> int | None:
    for idx, source in enumerate(key_sources):
        if source.get("source") in ("msg_sender", "tx_origin", "signature_recovery"):
            return idx
    return None


def _event_hint_from_writer_spec(spec: WriterEventSpec, member_key_index: int) -> dict[str, Any]:
    topic0 = "0x" + keccak(text=spec["event_signature"]).hex()
    key_position = int(spec["key_position"])
    indexed_positions = [int(pos) for pos in spec.get("indexed_positions") or []]
    key_positions = spec.get("key_positions_by_index") or {member_key_index: key_position}
    topics_to_keys: dict[int, int] = {}
    data_to_keys: dict[int, int] = {}
    for key_index_raw, event_arg_position_raw in key_positions.items():
        key_index = int(key_index_raw)
        event_arg_position = int(event_arg_position_raw)
        topic_map, data_map = _event_arg_to_key_maps(
            event_arg_position=event_arg_position,
            key_index=key_index,
            indexed_positions=indexed_positions,
        )
        topics_to_keys.update(topic_map)
        data_to_keys.update(data_map)
    return {
        "topic0": topic0,
        "topics_to_keys": topics_to_keys,
        "data_to_keys": data_to_keys,
        "direction": spec["direction"],
        "event_signature": spec["event_signature"],
        "event_name": spec["event_name"],
        "mapping_name": spec["mapping_name"],
        "key_position": key_position,
        "indexed_positions": indexed_positions,
        "value_position": spec.get("value_position"),
        "writer_function": spec.get("writer_function"),
    }


def _event_arg_to_key_maps(
    *,
    event_arg_position: int,
    key_index: int,
    indexed_positions: list[int],
) -> tuple[dict[int, int], dict[int, int]]:
    if event_arg_position in indexed_positions:
        return {1 + indexed_positions.index(event_arg_position): key_index}, {}
    data_position = sum(1 for pos in range(event_arg_position + 1) if pos not in indexed_positions) - 1
    return {}, {data_position: key_index}


def _hint_identity(hint: dict[str, Any]) -> tuple[Any, ...]:
    return (
        hint.get("topic0"),
        hint.get("direction"),
        hint.get("event_signature"),
        hint.get("key_position"),
        hint.get("value_position"),
    )


def _is_externally_callable(fn: Any) -> bool:
    """External or public visibility, AND not a constructor /
    fallback / receive special function. Modifiers are not
    functions in this sense."""
    visibility = getattr(fn, "visibility", None)
    if visibility not in ("external", "public"):
        return False
    if getattr(fn, "is_constructor", False):
        return False
    # Slither tags special functions via name; receive/fallback also
    # have non-standard signatures.
    name = getattr(fn, "name", "") or ""
    if name in ("constructor", "fallback", "receive"):
        return False
    if getattr(fn, "is_fallback", False) or getattr(fn, "is_receive", False):
        return False
    return True
