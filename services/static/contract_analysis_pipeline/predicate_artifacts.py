"""Build the predicate-tree artifact: ``build_predicate_tree`` per function plus the contract-wide writer-gate and
reentrancy/pause passes, keyed by entry-point full name.

A present tree means the function is guarded by it; absent means unguarded. Only external/public entry points (plus
fallback/receive attempts) appear.
"""

from __future__ import annotations

import logging
import math
import os
import time
from collections.abc import Callable
from typing import Any

from eth_utils.crypto import keccak

from utils.logging import record_stage_metric

from .authorization import apply_authorization_pass
from .internal_authority_slot import apply_internal_authority_slot_pass
from .mapping_events import WriterEventSpec, discover_mapping_writer_events
from .one_shot import apply_one_shot_pass
from .predicate_types import PredicateTree, mark_operand_absorption_recorded
from .predicates import _helper_engine_cache, build_predicate_tree, build_return_predicate_tree
from .reentrancy_pause import PauseInfo, apply_reentrancy_pause_pass
from .structural_evidence import structural_scope
from .writer_gate import apply_writer_gate_pass

logger = logging.getLogger(__name__)

SCHEMA_VERSION = "semantic"


def _slow_function_threshold_ms() -> int:
    """Functions slower than this log ``predicate_function_slow`` so Loki can rank hot spots.

    Env ``PSAT_PREDICATE_FUNCTION_SLOW_MS`` (default 250).
    """
    try:
        return max(0, int(os.getenv("PSAT_PREDICATE_FUNCTION_SLOW_MS", "250")))
    except ValueError:
        return 250


def _predicate_summary_threshold_ms() -> int:
    """Per-contract summary only above this. Env ``PSAT_PREDICATE_SUMMARY_MS`` (default 500)."""
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


def _lower_type_to_abi(t: Any, ancestors: tuple[Any, ...]) -> str:
    """Lower a Slither parameter type to its canonical ABI string (contract/interface to ``address``, enum to
    ``uint<N>``, struct to a tuple, alias to its underlying type, arrays keep their suffix). ``ancestors`` is the
    enclosing struct path, so a self-recursive struct stops (keeping its name for the caller to drop) while a type
    repeated across siblings still lowers.
    """
    from slither.core.declarations import Contract, Enum, Structure
    from slither.core.solidity_types import ArrayType, UserDefinedType
    from slither.core.solidity_types.type_alias import TypeAlias

    if isinstance(t, ArrayType):
        element = _lower_type_to_abi(t.type, ancestors)
        if t.length is None:
            return element + "[]"
        return f"{element}[{t.length_value}]"

    if isinstance(t, TypeAlias):
        return str(t.type)

    if isinstance(t, UserDefinedType):
        underlying = t.type
        if isinstance(underlying, Contract):
            return "address"
        if isinstance(underlying, Enum):
            count = len(underlying.values)
            width = 8 if count <= 256 else (16 if count <= 65536 else int(math.log2(count)))
            return f"uint{width}"
        if isinstance(underlying, Structure):
            if underlying in ancestors:
                # Self-recursive struct: unlowerable, surface the name.
                return str(t)
            members = ",".join(_lower_type_to_abi(e.type, ancestors + (underlying,)) for e in underlying.elems_ordered)
            return f"({members})"

    return str(t)


def _canonical_signature(fn: Any) -> str | None:
    """The canonical ABI signature for ``fn``, or ``None`` if it can't be fully lowered.

    Full names keep user-defined types (``addAsset(ERC20)``), and struct layouts and enum widths can't be recovered from
    the string later, so lower from the live Slither types. A residual non-elementary token rejects the signature
    (string fallback).
    """
    try:
        parameters = fn.parameters
        name = fn.name
    except (AttributeError, KeyError, TypeError):
        return None
    if parameters is None or not isinstance(name, str):
        return None
    try:
        lowered = [_lower_type_to_abi(p.type, ()) for p in parameters]
    except (ValueError, AttributeError, KeyError, TypeError):
        return None
    signature = f"{name}({','.join(lowered)})"
    # A surviving user-defined name means an unlowerable recursive struct.
    if any(seg and not _is_elementary_token(seg) for seg in _split_top_level(",".join(lowered))):
        return None
    return signature


def dispatch_signature(callee: Any, declared_signature: str | None = None) -> str | None:
    """The canonical ABI signature a call to ``callee`` dispatches on, or ``None`` when it can't be determined.

    Lowered from the live Slither types; a public state variable's getter uses Slither's own lowered signature.
    ``declared_signature`` (Slither's spelling) stands in only when it is already canonical, since an unlowered name
    hashes to a selector the chain never dispatches. A library hashes struct, enum and contract parameters by name and
    suffixes storage parameters with `` storage``; neither form is reproduced, so those functions are undetermined
    (:func:`_library_signature`).
    """
    from slither.core.variables.state_variable import StateVariable

    signature: str | None = None
    if isinstance(callee, StateVariable):
        try:
            signature = callee.solidity_signature
        except (AttributeError, KeyError, TypeError, ValueError):
            signature = None
    elif getattr(getattr(callee, "contract_declarer", None), "is_library", False):
        return _library_signature(callee)
    elif callee is not None:
        signature = _canonical_signature(callee)
    if signature is None:
        signature = declared_signature
    return signature if isinstance(signature, str) and is_canonical_abi_signature(signature) else None


def _library_signature(fn: Any) -> str | None:
    """A library function's selector signature where it equals the ABI form: elementary parameters, value types as
    their underlying type, arrays of those. Anything solc hashes by name or location is undetermined.
    """
    from slither.core.solidity_types import ArrayType, ElementaryType
    from slither.core.solidity_types.type_alias import TypeAlias

    def lower(t: Any) -> str | None:
        if isinstance(t, ArrayType):
            element = lower(t.type)
            if element is None:
                return None
            return element + ("[]" if t.length is None else f"[{t.length_value}]")
        if isinstance(t, TypeAlias):
            return str(t.type)
        if isinstance(t, ElementaryType):
            return str(t)
        return None

    try:
        parameters = list(fn.parameters)
        name = fn.name
    except (AttributeError, KeyError, TypeError):
        return None
    if not isinstance(name, str) or any(getattr(p, "location", None) == "storage" for p in parameters):
        return None
    lowered = [lower(p.type) for p in parameters]
    if any(token is None for token in lowered):
        return None
    signature = f"{name}({','.join(str(token) for token in lowered)})"
    return signature if is_canonical_abi_signature(signature) else None


def dispatch_selector(callee: Any, declared_signature: str | None = None) -> str | None:
    """``keccak256[:4]`` of :func:`dispatch_signature`, or ``None``."""
    signature = dispatch_signature(callee, declared_signature)
    return None if signature is None else "0x" + keccak(text=signature).hex()[:8]


_ELEMENTARY_PREFIXES = (
    "uint",
    "int",
    "bytes",
    "address",
    "bool",
    "string",
    "fixed",
    "ufixed",
)


def _is_elementary_token(token: str) -> bool:
    """True when ``token`` is an elementary type or a tuple of them."""
    token = token.strip()
    while token.endswith("]"):
        token = token[: token.rindex("[")]
    if token.startswith("(") and token.endswith(")"):
        return all(_is_elementary_token(s) for s in _split_top_level(token[1:-1]) if s)
    return token.startswith(_ELEMENTARY_PREFIXES)


# Slither renders the selectorless entry points as zero-arg signatures whose hashes are no dispatch (a real ``function
# fallback()`` would own that selector).
SELECTORLESS_SIGNATURES = frozenset({"fallback()", "receive()"})


def has_no_selector(signature: str | None) -> bool:
    """True for signatures that provably have no selector, unlike an unlowered one (unknown).

    Consumers publish ``""`` for these (``db/effect_cache.py``'s sentinel) and ``None`` for unlowered.
    """
    return signature in SELECTORLESS_SIGNATURES


def is_canonical_abi_signature(signature: str) -> bool:
    """True when every parameter is elementary, so ``keccak(signature)[:4]`` is the real selector.

    Shared so every string-based selector derivation fails closed on unlowered names; fallback/receive are rejected too.
    """
    if has_no_selector(signature):
        return False
    if "(" not in signature or not signature.endswith(")"):
        return False
    body = signature[signature.index("(") + 1 : -1]
    return all(_is_elementary_token(token) for token in _split_top_level(body) if token.strip())


def _split_top_level(s: str) -> list[str]:
    out: list[str] = []
    depth = 0
    start = 0
    for i, ch in enumerate(s):
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        elif ch == "," and depth == 0:
            out.append(s[start:i])
            start = i + 1
    out.append(s[start:])
    return out


def build_predicate_artifacts(contract: Any) -> dict[str, Any]:
    """Predicate trees for every external/public function; functions without revert paths are omitted (read as
    unguarded).
    """
    artifact, _ = build_predicate_artifacts_with_pause_info(contract)
    return artifact


def build_predicate_artifacts_with_pause_info(contract: Any) -> tuple[dict[str, Any], PauseInfo]:
    with structural_scope(contract) as evidence:
        artifact, pause_info = _build_predicate_artifacts_with_pause_info(contract)
        artifact["structural_evidence"] = evidence.publish()
        return artifact, pause_info


def _build_predicate_artifacts_with_pause_info(
    contract: Any,
) -> tuple[dict[str, Any], PauseInfo]:
    """The predicate artifact plus ``PauseInfo`` for ``_detect_pausability``, with per-function timing logs above
    ``_slow_function_threshold_ms()`` and a summary above ``_predicate_summary_threshold_ms()``.
    """
    contract_name = getattr(contract, "name", None)
    per_function_ms: list[tuple[str, int]] = []
    slow_threshold_ms = _slow_function_threshold_ms()
    pass_durations_ms: dict[str, int] = {}
    fns_attempted = 0

    started = time.monotonic()
    # Per-contract helper-engine cache; functions share helper guards.
    cache_token = _helper_engine_cache.set({})
    try:
        trees: dict[str, PredicateTree] = {}
        check_trees: dict[str, PredicateTree] = {}
        # Entry points whose caller-authority EQ/NEQ guard couldn't be lowered; policy must not default them to public.
        guard_uncertain: set[str] = set()
        # full_name -> canonical signature where they differ, so selector consumers key on the real ``msg.sig``.
        canonical_signatures: dict[str, str] = {}
        # ``functions_entry_points`` is deduped. ``functions`` includes shadowed bases of overridden virtuals, which the
        # builder ran fully and then discarded (~146 s per contract on CumulativeMerkleDrop).
        for fn in getattr(contract, "functions_entry_points", []) or []:
            if not _is_predicate_target(fn):
                continue
            fns_attempted += 1
            # No selector to canonicalize.
            if not _is_fallback_or_receive(fn):
                canonical = dispatch_signature(fn, fn.full_name)
                if canonical is not None and canonical != fn.full_name:
                    canonical_signatures[fn.full_name] = canonical
            fn_started = time.monotonic()
            tree = build_predicate_tree(fn, uncertain_out=guard_uncertain)
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
    # Contract-wide passes mutate trees: writer-gate promotes single-key membership leaves once all writers are known,
    # and reentrancy/pause cross-references state vars.
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

        # After reentrancy/pause, so guard leaves they claimed keep their classification.
        pass_started = time.monotonic()
        apply_one_shot_pass(contract, all_trees)
        pass_durations_ms["one_shot"] = int((time.monotonic() - pass_started) * 1000)

        trees = {sig: all_trees[sig] for sig in trees}
        check_trees = {sig: all_trees[check_tree_keys[sig]] for sig in check_trees}

    apply_authorization_pass(contract, trees)

    # Attempted vs built: unguarded functions produce no tree, so the gap is normal, not degradation.
    record_stage_metric("predicate_fns_attempted", fns_attempted)
    record_stage_metric("predicate_trees_built", len(trees))

    # Mark every finished tree after the contract-wide passes (a replaced root must read as unmarked). An operand
    # missing from a leaf is only evidence of absence on a marked tree; older persisted trees dropped comparison sides.
    # ``effects.calldata`` gates its indefinite-freeze state on this.
    for finished_tree in (*trees.values(), *check_trees.values()):
        mark_operand_absorption_recorded(finished_tree)

    artifact = {
        "schema_version": SCHEMA_VERSION,
        "contract_name": contract_name,
        "trees": trees,
    }
    if canonical_signatures:
        artifact["canonical_signatures"] = canonical_signatures
    if check_trees:
        artifact["check_trees"] = check_trees
    # Only functions still without a tree after the passes.
    residual_uncertain = sorted(guard_uncertain - set(trees))
    if residual_uncertain:
        artifact["guard_extraction_uncertain"] = residual_uncertain

    total_ms = int((time.monotonic() - started) * 1000)
    if total_ms >= _predicate_summary_threshold_ms():
        # Top 5 slowest functions, for Loki ranking.
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
    """Copy mapping-writer event evidence (``wards[user] = 1; emit Rely(user)``) onto matching ``mapping_membership``
    descriptors.
    """
    specs_by_mapping: dict[str, list[WriterEventSpec]] = {}
    for spec in discover_mapping_writer_events(contract):
        mapping_name = spec.get("mapping_name")
        if mapping_name:
            specs_by_mapping.setdefault(mapping_name, []).append(spec)

    if not specs_by_mapping:
        return

    def attach(leaf: dict[str, Any]) -> None:
        _attach_hints_to_leaf(leaf, specs_by_mapping)
        _attach_value_specs_to_param_keyed_operands(leaf, specs_by_mapping)

    for tree in trees.values():
        _walk_tree_leaves(tree, attach)


def _attach_value_specs_to_param_keyed_operands(
    leaf: dict[str, Any], specs_by_mapping: dict[str, list[WriterEventSpec]]
) -> None:
    """Attach ``set``-direction writer specs to ``msg.sender == mapping[param]`` operands (``mapping_name`` stamped
    by the builder), so resolution can fold the mapping's value set. The setter (``setReceiver`` ->
    ``ReceiverSet``) is another function, so this only works contract-wide.
    """
    if leaf.get("kind") != "equality":
        return
    for op in leaf.get("operands") or []:
        if not isinstance(op, dict):
            continue
        mapping_name = op.get("mapping_name")
        if not isinstance(mapping_name, str) or not mapping_name:
            continue
        value_specs = [
            _value_writer_spec(spec)
            for spec in specs_by_mapping.get(mapping_name) or []
            if spec.get("direction") == "set" and spec.get("value_position") is not None
        ]
        if value_specs:
            op["mapping_writer_specs"] = value_specs


def _value_writer_spec(spec: WriterEventSpec) -> dict[str, Any]:
    """The WriterEventSpec subset the value enumerator uses, without the int-keyed ``key_positions_by_index`` (JSONB
    would coerce the keys).
    """
    return {
        "mapping_name": spec["mapping_name"],
        "event_signature": spec["event_signature"],
        "event_name": spec["event_name"],
        "key_position": int(spec["key_position"]),
        "indexed_positions": [int(pos) for pos in spec.get("indexed_positions") or []],
        "direction": "set",
        "writer_function": spec.get("writer_function") or "",
        "value_position": int(spec["value_position"]),  # pyright: ignore[reportArgumentType]
    }


# Solmate ``requiresAuth`` checks ``authority.canCall(msg.sender, address(this), msg.sig)``. Attach the RolesAuthority
# role-event topics so the indexer enrolls them; canCall is a two-event join the generic mapping path can't cover.
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


def _is_fallback_or_receive(fn: Any) -> bool:
    if getattr(fn, "is_fallback", False) or getattr(fn, "is_receive", False):
        return True
    return (getattr(fn, "name", "") or "") in ("fallback", "receive")


def _is_externally_callable(fn: Any) -> bool:
    """External/public and not a constructor, fallback or receive: the selector-bearing surface (narrower than
    ``_is_predicate_target``).
    """
    visibility = getattr(fn, "visibility", None)
    if visibility not in ("external", "public"):
        return False
    if getattr(fn, "is_constructor", False):
        return False
    if (getattr(fn, "name", "") or "") == "constructor":
        return False
    if _is_fallback_or_receive(fn):
        return False
    return True


def _is_predicate_target(fn: Any) -> bool:
    """The selector-bearing surface plus fallback/receive.

    They have callers: without a tree, an ``onlyOwner`` fallback looked identical to an open one, so a tree must be
    attempted to tell "not attempted" from "nothing there".
    """
    if getattr(fn, "is_constructor", False) or (getattr(fn, "name", "") or "") == "constructor":
        return False
    if _is_fallback_or_receive(fn):
        return True
    return _is_externally_callable(fn)
