"""Build transient permission rows from semantic resolver output."""

from __future__ import annotations

import logging
from dataclasses import is_dataclass
from typing import Any, Mapping, cast

from eth_utils.crypto import keccak

from schemas.observations import ObservationBatch, coerce_resolved_controller_type
from schemas.permission_index import (
    AuthorityRoleGrant,
    PermissionIndex,
    PermissionRow,
    PrincipalResolution,
    ResolvedAddressType,
    ResolvedControllerGrant,
    ResolvedPrincipal,
)
from schemas.static_facts import StaticFacts
from services.policy.capability_surface import (
    capability_role_grants,
    capability_surface_openness,
    capability_surface_status,
    project_capability_surface,
)
from services.static.static_analysis.predicate_artifacts import (
    _split_top_level,
    has_no_selector,
    is_canonical_abi_signature,
)
from utils.logging import record_degraded

logger = logging.getLogger(__name__)

ELEMENTARY_TYPE_PREFIXES = (
    "address",
    "uint",
    "int",
    "bool",
    "bytes",
    "string",
    "fixed",
    "ufixed",
    "tuple",
)


def _lower_string(value: Any) -> str:
    if value is None:
        return ""
    return str(value).lower()


def _normalize_abi_type(type_name: str) -> str:
    stripped = type_name.strip()
    if not stripped:
        return stripped

    if stripped.startswith("DynArray[") and stripped.endswith("]"):
        inner = stripped[len("DynArray[") : -1]
        parts = inner.split(",", 1)
        return f"{_normalize_abi_type(parts[0])}[]"
    if stripped.startswith("HashMap[") and stripped.endswith("]"):
        return "mapping"
    if stripped.startswith("String[") and stripped.endswith("]"):
        return "string"
    if stripped.startswith("Bytes[") and stripped.endswith("]"):
        return "bytes"
    if stripped.endswith("]"):
        if "[" not in stripped:
            return "address"
        base, suffix = stripped.split("[", 1)
        return f"{_normalize_abi_type(base)}[{suffix}"

    # An already-lowered tuple is canonical ABI; collapsing it to ``address``
    # would destroy an arity a caller had already recovered. Parentheses are not
    # legal in a user-defined type name, so this test cannot misfire.
    if stripped.startswith("(") and stripped.endswith(")"):
        members = [m for m in _split_top_level(stripped[1:-1]) if m.strip()]
        return "(" + ",".join(_normalize_abi_type(m) for m in members) + ")"

    if stripped.startswith(ELEMENTARY_TYPE_PREFIXES):
        return stripped

    # ``A.B`` is a struct / enum / user-defined value type declared inside ``A``.
    # Solidity has no nested contracts, so a qualified token is provably NOT a
    # contract reference and ``address`` is the wrong lowering — while the right
    # one (a struct's field layout, an enum's width) is not recoverable from a
    # name. Leave it un-lowered so a selector derived from this string fails
    # closed instead of naming a dispatch that does not exist.
    if "." in stripped:
        return stripped

    # A bare user-defined name stays ``address``: it is a contract reference more
    # often than not, and a name alone cannot tell a contract from a file-level
    # struct or enum. The canonical map above is what resolves it properly.
    return "address"


def _abi_signature(function_signature: str) -> str:
    if "(" not in function_signature or not function_signature.endswith(")"):
        return function_signature
    name, args = function_signature.split("(", 1)
    args = args[:-1]
    if not args:
        return f"{name}()"
    raw_args: list[str] = []
    current: list[str] = []
    depth = 0
    for char in args:
        if char in "([{":
            depth += 1
        elif char in ")]}":
            depth = max(depth - 1, 0)
        if char == "," and depth == 0:
            piece = "".join(current).strip()
            if piece:
                raw_args.append(piece)
            current = []
            continue
        current.append(char)
    piece = "".join(current).strip()
    if piece:
        raw_args.append(piece)
    normalized_args = ",".join(_normalize_abi_type(arg) for arg in raw_args)
    return f"{name}({normalized_args})"


def _canonical_signature_map(predicate_trees: Mapping[str, Any] | None) -> dict[str, str]:
    """``full_name -> EVM-canonical ABI signature`` from the predicate artifact.

    The static stage precomputes this from Slither's ``solidity_signature`` (see
    ``predicate_artifacts._canonical_signature``) so the selector here keys on
    the true ``msg.sig`` for contract/enum/struct params. ``_abi_signature``'s
    string-level normalization can only recover contract params (→ ``address``);
    enums (→ ``uint8``) and structs (→ tuple) need the type info this map carries."""
    if not isinstance(predicate_trees, dict):
        return {}
    canonical = predicate_trees.get("canonical_signatures")
    if not isinstance(canonical, dict):
        return {}
    return {
        str(name): str(sig)
        for name, sig in canonical.items()
        if isinstance(sig, str) and "(" in sig and sig.endswith(")")
    }


def _abi_signature_and_selector(
    function_signature: str, canonical_signatures: Mapping[str, str]
) -> tuple[str, str | None]:
    """``(abi_signature, selector)`` preferring the precomputed canonical ABI
    signature; falls back to the full_name string normalization when absent.

    The selector is ``None`` when the fallback could not fully lower the
    signature. Hashing a string that still names a user-defined type publishes a
    4-byte value the chain will never dispatch on, and the row's own signature
    column would then disagree with its selector — a wrong answer where no
    answer is the honest one.

    It is ``""`` for ``fallback()`` / ``receive()``: those PROVABLY have no
    selector, which is a different answer from "we could not derive one", and
    ``""`` is the sentinel ``db/effect_cache.py`` already fixes for them."""
    abi_sig = canonical_signatures.get(function_signature) or _abi_signature(function_signature)
    if has_no_selector(abi_sig):
        return abi_sig, ""
    if not is_canonical_abi_signature(abi_sig):
        return abi_sig, None
    return abi_sig, "0x" + keccak(text=abi_sig).hex()[:8]


def _resolved_principal(
    address: str,
    resolved_type: ResolvedAddressType,
    details: dict[str, object],
    *,
    source_contract: str | None = None,
    source_controller_id: str | None = None,
) -> ResolvedPrincipal:
    payload: ResolvedPrincipal = {
        "address": address,
        "resolved_type": resolved_type,
        "details": details,
    }
    if source_contract is not None:
        payload["source_contract"] = source_contract
    if source_controller_id is not None:
        payload["source_controller_id"] = source_controller_id
    return payload


def _known_principals(*snapshots: Mapping[str, Any] | None) -> dict[str, ResolvedPrincipal]:
    known: dict[str, ResolvedPrincipal] = {}
    for snapshot in snapshots:
        if not snapshot:
            continue
        contract_name = str(snapshot.get("contract_name", ""))
        controller_values = snapshot.get("controller_values", {})
        if not isinstance(controller_values, dict):
            continue
        for controller_id, value in controller_values.items():
            if not isinstance(controller_id, str) or not isinstance(value, dict):
                continue
            address_raw = value.get("value", "")
            address = _lower_string(address_raw)
            if not address.startswith("0x"):
                continue
            details_raw = value.get("details", {})
            details = dict(details_raw) if isinstance(details_raw, dict) else {}
            known[address] = _resolved_principal(
                address,
                coerce_resolved_controller_type(value.get("resolved_type")),
                details,
                source_contract=contract_name,
                source_controller_id=controller_id,
            )
    return known


def _principal_for_address(address: str, known: dict[str, ResolvedPrincipal]) -> ResolvedPrincipal:
    normalized = address.lower()
    return known.get(normalized) or _resolved_principal(normalized, "unknown", {})


def _controller_lookup(snapshot: Mapping[str, Any] | None) -> dict[str, list[tuple[str, dict[str, Any]]]]:
    lookup: dict[str, list[tuple[str, dict[str, Any]]]] = {}
    controller_values = (snapshot or {}).get("controller_values", {})
    if not isinstance(controller_values, dict):
        return lookup
    for controller_id, value in controller_values.items():
        if not isinstance(controller_id, str) or not isinstance(value, dict):
            continue
        source = str(value.get("source", controller_id))
        lookup.setdefault(source, []).append((controller_id, value))
    return lookup


def _controller_grants_for_refs(
    controller_refs: list[str],
    controller_lookup: dict[str, list[tuple[str, dict[str, Any]]]],
    known: dict[str, ResolvedPrincipal],
) -> list[ResolvedControllerGrant]:
    grants: list[ResolvedControllerGrant] = []
    seen: set[str] = set()
    for ref in controller_refs:
        for controller_id, value in controller_lookup.get(ref, []):
            if controller_id in seen:
                continue
            seen.add(controller_id)
            raw_value = _lower_string(value.get("value", ""))
            principals: list[ResolvedPrincipal] = []
            notes: list[str] = []
            details_raw = value.get("details", {})
            details = dict(details_raw) if isinstance(details_raw, dict) else {}
            raw_principals = details.get("resolved_principals", [])
            if isinstance(raw_principals, list):
                for principal in raw_principals:
                    if not isinstance(principal, dict):
                        continue
                    address = str(principal.get("address", "")).lower()
                    if not address.startswith("0x"):
                        continue
                    principal_details_raw = principal.get("details", {})
                    principal_details = dict(principal_details_raw) if isinstance(principal_details_raw, dict) else {}
                    principals.append(
                        _resolved_principal(
                            address,
                            coerce_resolved_controller_type(principal.get("resolved_type")),
                            principal_details,
                            source_controller_id=controller_id,
                        )
                    )
            if (
                raw_value.startswith("0x")
                and len(raw_value) == 42
                and raw_value != "0x0000000000000000000000000000000000000000"
            ):
                kind = controller_id.split(":", 1)[0] if ":" in controller_id else "unknown"
                if not principals and kind in {"state_variable", "singleton_slot", "computed"}:
                    principals.append(_principal_for_address(raw_value, known))
            elif raw_value and not principals:
                notes.append(f"value={raw_value}")
            kind = controller_id.split(":", 1)[0] if ":" in controller_id else "unknown"
            if not principals:
                continue
            grants.append(
                {
                    "controller_id": controller_id,
                    "label": ref,
                    "kind": kind,
                    "principals": principals,
                    "notes": notes,
                }
            )
    return grants


def _normalize_capability_output(
    capability_resolver_output: Mapping[str, Any] | None,
) -> dict[str, dict[str, Any]]:
    """``capability_resolver_output`` may carry either dataclass
    ``CapabilityExpr`` instances (from a direct resolver call) or
    already-serialized dicts (from a persisted artifact / test
    fixture). Normalize to dicts up-front so downstream column shaping
    has one shape to handle."""
    if not capability_resolver_output:
        return {}
    out: dict[str, dict[str, Any]] = {}
    for fn_signature, cap in capability_resolver_output.items():
        if cap is None:
            continue
        if isinstance(cap, dict):
            cap_dict = dict(cap)
            if not isinstance(cap_dict.get("kind"), str):
                cap_dict = _unsupported_capability("malformed_semantic_capability")
            out[str(fn_signature)] = cap_dict
            continue
        if is_dataclass(cap):
            try:
                from services.resolution.capability_resolver import capability_to_dict

                cap_dict = capability_to_dict(cap)  # pyright: ignore[reportArgumentType]
                if not isinstance(cap_dict.get("kind"), str):
                    cap_dict = _unsupported_capability("malformed_semantic_capability")
                out[str(fn_signature)] = cap_dict
            except Exception as exc:
                record_degraded(
                    phase="capability_serialization",
                    exc=exc,
                    context={"fn_signature": str(fn_signature)},
                )
                logger.warning(
                    "Failed to serialize CapabilityExpr for function %s: %s",
                    fn_signature,
                    exc,
                )
                out[str(fn_signature)] = _unsupported_capability("malformed_semantic_capability")
            continue
        out[str(fn_signature)] = _unsupported_capability("malformed_semantic_capability")
    return out


def _unsupported_capability(reason: str) -> dict[str, Any]:
    return {
        "kind": "unsupported",
        "unsupported_reason": reason,
        "membership_quality": "exact",
        "confidence": "check_only",
    }


def _public_capability() -> dict[str, Any]:
    return {
        "kind": "conditional_universal",
        "conditions": [],
        "membership_quality": "exact",
        "confidence": "enumerable",
    }


def _effects_by_function(
    effects: Mapping[str, Any] | None,
) -> dict[str, dict[str, Any]]:
    """The semantic ``effects`` artifact keyed by function full-name.
    Returns a flat ``{function_signature: effect_record}`` dict where each
    record carries claims and mutability evidence.

    Falls back to ``{}`` if the artifact is missing or malformed."""
    if not isinstance(effects, dict):
        return {}
    functions = effects.get("functions")
    if not isinstance(functions, dict):
        return {}
    return {str(fn_sig): record for fn_sig, record in functions.items() if isinstance(record, dict)}


def _predicate_trees_by_function(predicate_trees: Mapping[str, Any] | None) -> dict[str, dict[str, Any]]:
    if not isinstance(predicate_trees, dict):
        return {}
    trees = predicate_trees.get("trees")
    if not isinstance(trees, dict):
        return {}
    return {str(fn_sig): tree for fn_sig, tree in trees.items() if isinstance(tree, dict)}


def _guard_uncertain_signatures(predicate_trees: Mapping[str, Any] | None) -> frozenset[str]:
    """Full-names the static stage flagged as a caller-authority guard it could
    not lower into a tree (``guard_extraction_uncertain``). The policy fails
    these closed (``unsupported``) instead of defaulting them to public."""
    if not isinstance(predicate_trees, dict):
        return frozenset()
    flagged = predicate_trees.get("guard_extraction_uncertain")
    if not isinstance(flagged, (list, set, tuple)):
        return frozenset()
    return frozenset(str(sig) for sig in flagged)


def _controller_refs_from_tree(tree: Mapping[str, Any] | None) -> list[str]:
    if not isinstance(tree, dict):
        return []
    refs: list[str] = []
    seen: set[str] = set()

    def add(name: Any) -> None:
        if isinstance(name, str) and name and name not in seen:
            seen.add(name)
            refs.append(name)

    def visit(node: Any) -> None:
        if not isinstance(node, dict):
            return
        if node.get("op") == "LEAF":
            leaf = node.get("leaf") or {}
            if not isinstance(leaf, dict):
                return
            for operand in leaf.get("operands") or []:
                if isinstance(operand, dict) and operand.get("source") == "state_variable":
                    add(operand.get("state_variable_name"))
            descriptor = leaf.get("set_descriptor") or {}
            if isinstance(descriptor, dict):
                authority = descriptor.get("authority_contract") or {}
                if isinstance(authority, dict):
                    address_source = authority.get("address_source") or {}
                    if isinstance(address_source, dict) and address_source.get("source") == "state_variable":
                        add(address_source.get("state_variable_name"))
                for key_source in descriptor.get("key_sources") or []:
                    if isinstance(key_source, dict) and key_source.get("source") == "state_variable":
                        add(key_source.get("state_variable_name"))
            return
        for child in node.get("children") or []:
            visit(child)

    visit(tree)
    return refs


_SENSITIVE_SINK_KINDS = frozenset({"state_write", "external_call", "delegatecall", "contract_creation", "selfdestruct"})


def _effect_record_has_sensitive_sink(record: Mapping[str, Any]) -> bool:
    for sink in record.get("sinks") or []:
        if isinstance(sink, dict) and sink.get("kind") in _SENSITIVE_SINK_KINDS:
            return True
    return False


def _effect_record_is_state_changing_entry_point(record: Mapping[str, Any]) -> bool:
    """True for a selector-bearing external/public, non-view, non-pure entry
    point. The static stage stamps ``state_changing`` from the verified
    function mutability so the ABI surface is visible here without re-running
    Slither; falsy/absent means a view/pure read or a non-selector function."""
    return record.get("state_changing") is True


#: The four ``EffectInfo`` mutability facts, in the order they are documented.
MUTABILITY_FIELDS = ("state_changing", "state_writes", "sinks", "writer_selectors")

_NOT_DETERMINED: dict[str, Any] = dict.fromkeys(MUTABILITY_FIELDS)


def _is_unselectored_entry_point(signature: str) -> bool:
    """``fallback`` / ``receive`` — externally observable, but not selector-bearing."""
    return signature.split("(")[0] in ("fallback", "receive")


def _mutability_fields(record: Mapping[str, Any]) -> dict[str, Any]:
    """Project an effects ``EffectInfo`` onto the four persisted mutability columns.

    ``None`` on any field means NOT DETERMINED and is a different fact from
    ``false`` / ``[]``. Three record shapes produce it, all measured against the
    107 production ``effects`` artifacts (2415 function records):

    * **No record, or a malformed field.** A missing effects artifact is a live
      production branch — ``policy_worker`` passes ``effects=None`` whenever the
      artifact is not a dict and the stage continues — and a present-but-wrongly-
      typed value is not evidence of emptiness, so it does not collapse to ``[]``.

    * **``fallback`` / ``receive`` → ``state_changing`` is not determined** (36
      records; 15 of them carry a proven state write). ``_is_state_changing_entry_point``
      returns ``False`` for these because they have no selector, NOT because it
      proved them non-mutating: WETH9's ``fallback()`` writes ``balanceOf``.
      Copying that ``False`` into a column read as evidence would publish a proven
      absence over a proven presence. Their sinks and writes are real and are
      published.

    * **A view/pure entry point whose derived writes contradict it → the derived
      effect facts are not determined** (100 records). Records exist only for
      external/public/fallback/receive functions, so ``state_changing is False``
      on a named one means the compiler typed it ``view``/``pure`` — and the
      compiler forbids ``SSTORE`` there. The writes are OZ-v5 namespaced-storage
      getters (``paused()`` "writing" ``PausableStorageLocation``) and struct
      copies (``previewUpdateExchangeRate``); ``assembly_state_access`` is
      ``false`` on all 100, so nothing existing catches them. The contradiction is
      resolved in favour of the compiler for ``state_changing`` and withheld for
      everything derived from the same lowering — including ``sinks``, which
      carries the identical claim under a ``state_write`` kind tag.

    ``state_writes`` empty on a view is NOT a contradiction and stays ``[]``.
    """
    if not isinstance(record, Mapping) or not record:
        return dict(_NOT_DETERMINED)

    signature = str(record.get("function") or "")
    raw_state_changing = record.get("state_changing")
    state_changing = raw_state_changing if isinstance(raw_state_changing, bool) else None

    out: dict[str, Any] = {
        "state_changing": None if _is_unselectored_entry_point(signature) else state_changing,
        "state_writes": record.get("state_writes"),
        "sinks": record.get("sinks"),
        "writer_selectors": record.get("writer_selectors"),
    }
    if not isinstance(out["state_writes"], list):
        out["state_writes"] = None
    if not isinstance(out["sinks"], list):
        out["sinks"] = None
    if not isinstance(out["writer_selectors"], list) or not all(
        isinstance(sel, str) for sel in out["writer_selectors"]
    ):
        out["writer_selectors"] = None

    contradicts_view = (
        state_changing is False and not _is_unselectored_entry_point(signature) and bool(out["state_writes"])
    )
    if contradicts_view:
        out["state_writes"] = None
        out["sinks"] = None
        out["writer_selectors"] = None
    return out


def _function_records_from_semantic_artifacts(
    *,
    capability_dicts: Mapping[str, dict[str, Any]],
    effects_by_function: Mapping[str, dict[str, Any]],
    predicate_trees_by_function: Mapping[str, dict[str, Any]],
    resolver_output_available: bool,
    guard_uncertain_signatures: frozenset[str] = frozenset(),
) -> list[dict[str, Any]]:
    """Build effective-permission function records from semantic resolver/effects data.

    Rows are the union of the semantic artifacts (capabilities ∪ predicate trees
    ∪ effects with a sensitive sink) plus every state-changing external/public
    ABI entry point. The latter makes a mutator whose authority gate and writes
    live in inline assembly — invisible to the high-level IR as a sink or a
    predicate tree — a visible, honestly-flagged ``unsupported`` row rather than
    a silent omission. Such a row carries no capability and no tree, so no
    principals attach to it."""
    sink_signatures = {
        signature for signature, record in effects_by_function.items() if _effect_record_has_sensitive_sink(record)
    }
    abi_mutability_signatures = {
        signature
        for signature, record in effects_by_function.items()
        if _effect_record_is_state_changing_entry_point(record)
    }

    signatures = set(capability_dicts)
    signatures.update(predicate_trees_by_function)
    signatures.update(sink_signatures)
    signatures.update(abi_mutability_signatures)

    # A state-changing entry point with no capability, no tree, and no sensitive
    # sink is covered ONLY by its ABI mutability — its authority is unresolved
    # (the gate lives outside the high-level IR), so it is flagged unsupported,
    # never projected public.
    abi_only_signatures = (
        abi_mutability_signatures - set(capability_dicts) - set(predicate_trees_by_function) - sink_signatures
    )

    # A state-changing entry point whose visible state effect originates from
    # inline assembly (sstore/delegatecall) has the same authority blindness as
    # an abi-only mutator: its gate may also be inline assembly and therefore
    # invisible to the predicate pipeline. It now carries a sink (so it left
    # ``abi_only_signatures`` above), but with no capability and no tree it must
    # stay fail-closed (unsupported), never projected public.
    #
    # Scoped to state-changing entry points on purpose: a fallback/receive that
    # only assembly-delegatecalls (an EIP-1967 proxy passthrough) has no
    # authority gate by design, so it stays a genuine ``public`` row carrying
    # its ``delegatecall_execution`` label rather than being hidden.
    assembly_only_signatures = (
        {
            signature
            for signature, record in effects_by_function.items()
            if record.get("assembly_state_access") and _effect_record_is_state_changing_entry_point(record)
        }
        - set(capability_dicts)
        - set(predicate_trees_by_function)
    )

    records: list[dict[str, Any]] = []
    for signature in sorted(signatures):
        effect_info = effects_by_function.get(signature) or {}
        record: dict[str, Any] = {
            "function": signature,
            "controller_refs": _controller_refs_from_tree(predicate_trees_by_function.get(signature)),
            "claims": list(effect_info.get("claims") or []),
            **_mutability_fields(effect_info),
        }
        if signature not in capability_dicts:
            if signature in predicate_trees_by_function:
                record["capability_expr"] = _unsupported_capability("missing_semantic_capability_for_predicate_tree")
                record["status"] = "unsupported"
            elif signature in guard_uncertain_signatures:
                # The static stage found a caller-authority (msg.sender EQ/NEQ)
                # guard it could not lower into a tree. Absence here is "guard
                # not extracted", not "unguarded" — fail closed, never public.
                # Checked BEFORE the abi/assembly-only arms: a marked signature
                # is usually also state-changing, and the specific evidence ("a
                # caller guard was SEEN") must not be shadowed by the generic
                # "authority not extracted" reason.
                record["capability_expr"] = _unsupported_capability("guard_extraction_uncertain")
                record["status"] = "unsupported"
            elif signature in abi_only_signatures or signature in assembly_only_signatures:
                record["capability_expr"] = _unsupported_capability("assembly_only_authority_not_extracted")
                record["status"] = "unsupported"
            elif resolver_output_available:
                record["capability_expr"] = _public_capability()
                record["status"] = "public"
                record["authority_public"] = True
            else:
                record["capability_expr"] = _unsupported_capability("missing_semantic_capability_resolver_output")
                record["status"] = "unsupported"
        records.append(record)
    return records


def _column_values_for_capability(cap_dict: dict[str, Any]) -> dict[str, Any]:
    """Mirror of the writer's per-kind column rules — kept here so the
    artifact dict carries the right shape even when the writer isn't
    invoked (read-only callers like the recursive resolver)."""
    surface = project_capability_surface(cap_dict)
    conditions = surface.conditions
    out: dict[str, Any] = {
        "capability_expr": dict(cap_dict),
        "conditions": conditions or None,
        "status": capability_surface_status(cap_dict, surface),
        "authority_public": surface.authority_public,
        "authority_openness": capability_surface_openness(cap_dict, surface),
    }
    return out


def build_permission_index(
    target_analysis: Mapping[str, Any] | StaticFacts,
    *,
    target_snapshot: Mapping[str, Any] | ObservationBatch | None = None,
    authority_snapshot: Mapping[str, Any] | ObservationBatch | None = None,
    artifact_paths: dict[str, str] | None = None,
    principal_resolution: PrincipalResolution | None = None,
    predicate_trees: Mapping[str, Any] | None = None,
    capability_resolver_output: Mapping[str, Any] | None = None,
    effects: Mapping[str, Any] | None = None,
) -> PermissionIndex:
    """Build the ``permission_index`` artifact from semantic resolver/effects
    inputs only.

    ``capability_resolver_output`` is the per-function CapabilityExpr
    dict the resolver produces. Tests typically supply it directly to
    avoid spinning up Slither + the full adapter chain.

    ``effects`` is the semantic ``effects`` artifact keyed by function full-name.
    """
    contract_address = target_analysis["subject"]["address"].lower()
    contract_name = target_analysis["subject"]["name"]

    known = _known_principals(target_snapshot, authority_snapshot)
    controller_lookup = _controller_lookup(target_snapshot)
    canonical_signatures = _canonical_signature_map(predicate_trees)
    capability_dicts = _normalize_capability_output(capability_resolver_output)
    effects_by_function = _effects_by_function(effects)
    predicate_tree_functions = _predicate_trees_by_function(predicate_trees)
    guard_uncertain_signatures = _guard_uncertain_signatures(predicate_trees)
    function_records = _function_records_from_semantic_artifacts(
        capability_dicts=capability_dicts,
        effects_by_function=effects_by_function,
        predicate_trees_by_function=predicate_tree_functions,
        resolver_output_available=capability_resolver_output is not None,
        guard_uncertain_signatures=guard_uncertain_signatures,
    )

    functions: list[PermissionRow] = []
    for function_record in function_records:
        abi_signature, selector = _abi_signature_and_selector(function_record["function"], canonical_signatures)
        controller_refs = sorted(set(function_record.get("controller_refs", [])))
        direct_owner = None

        notes: list[str] = []
        controller_grants = _controller_grants_for_refs(
            controller_refs,
            controller_lookup,
            known,
        )

        # The ``effects`` artifact is the source of truth for claims.
        fn_signature = function_record["function"]
        effects_record = effects_by_function.get(fn_signature) or {}
        semantic_claims = effects_record.get("claims") if effects_record else None

        claims_out = (
            list(semantic_claims) if isinstance(semantic_claims, list) else list(function_record.get("claims", []))
        )

        # Three-state role half (see ``capability_role_grants``): the
        # capability's own verdict replaces the historical literal ``[]`` that
        # every one of 1,773 persisted rows carried. The verdict is read from
        # whichever capability THIS record actually carries — the resolver's
        # when it produced one, otherwise the policy-minted shape
        # (``_public_capability`` / ``_unsupported_capability``): those rows
        # are published with a capability_expr, so their role half must be the
        # projection of that same dict, not a blanket ``None``. ``None`` is
        # reserved for a record carrying no capability at all ("nothing was
        # read").
        resolved_capability = capability_dicts.get(fn_signature)
        minted_capability = function_record.get("capability_expr")
        role_source_capability = (
            resolved_capability
            if resolved_capability is not None
            else (minted_capability if isinstance(minted_capability, dict) else None)
        )
        authority_roles_out = cast(
            "list[AuthorityRoleGrant] | None",
            capability_role_grants(role_source_capability) if role_source_capability is not None else None,
        )

        function_permission: PermissionRow = {
            "function": fn_signature,
            "abi_signature": abi_signature,
            "selector": selector,
            "direct_owner": direct_owner,
            "authority_public": False,
            "authority_roles": authority_roles_out,
            "controllers": controller_grants,
            "claims": claims_out,
            "notes": notes,
        }
        # The artifact is what ``policy_worker`` hands the row writer, so the
        # mutability witness has to survive this hop or the columns are NULL in
        # production while every record-layer test passes.
        mutability = _mutability_fields(effects_record)
        function_permission["state_changing"] = mutability["state_changing"]
        function_permission["state_writes"] = mutability["state_writes"]
        function_permission["sinks"] = mutability["sinks"]
        function_permission["writer_selectors"] = mutability["writer_selectors"]

        # Semantic capability columns: when a CapabilityExpr is supplied for this
        # function, it dictates capability_expr / conditions / status /
        # authority_public. The dict-form override here lets the writer
        # propagate these columns onto EffectiveFunction without re-resolving.
        cap_dict = capability_dicts.get(fn_signature)
        if cap_dict is not None:
            cap_columns = _column_values_for_capability(cap_dict)
            function_permission["capability_expr"] = cap_columns["capability_expr"]
            if cap_columns["conditions"] is not None:
                function_permission["conditions"] = cap_columns["conditions"]
            if cap_columns["status"] is not None:
                function_permission["status"] = cap_columns["status"]
            # conditional_universal short-circuits authority_public.
            if cap_columns["authority_public"]:
                function_permission["authority_public"] = True
            # The three-state verdict travels WITH the record: the writer's
            # ``cap_dict is None`` branch reads ``fn.get("authority_openness")``,
            # so dropping it here left the column NULL on every row the policy
            # layer minted — and NULL is documented as "written before the
            # column existed", which is false for a fresh row.
            function_permission["authority_openness"] = cap_columns["authority_openness"]
        else:
            if function_record.get("capability_expr") is not None:
                function_permission["capability_expr"] = function_record["capability_expr"]
            if function_record.get("conditions") is not None:
                function_permission["conditions"] = function_record["conditions"]
            if function_record.get("status") is not None:
                function_permission["status"] = function_record["status"]
            if function_record.get("authority_public") is True:
                function_permission["authority_public"] = True
            # Policy-minted capabilities (``_public_capability`` /
            # ``_unsupported_capability``) get the SAME openness projection a
            # resolver capability gets: ``open`` for the earned-public
            # fall-through, ``not_determined`` for every fail-closed reroute
            # (guard_extraction_uncertain / assembly_only / resolver-missing).
            # The answer was already computable from the dict this record
            # publishes; leaving the key absent published NULL with a meaning
            # ("pre-column legacy row") the row does not have.
            if isinstance(minted_capability, dict):
                minted_surface = project_capability_surface(minted_capability)
                function_permission["authority_openness"] = capability_surface_openness(
                    minted_capability, minted_surface
                )

        functions.append(function_permission)

    return {
        "schema_version": "0.1",
        "contract_address": contract_address,
        "contract_name": contract_name,
        "authority_contract": None,
        "principal_resolution": principal_resolution
        or {
            "status": "complete",
            "reason": "Semantic capability resolver output was joined into the permission view.",
        },
        "artifacts": artifact_paths or {},
        "functions": functions,
    }
