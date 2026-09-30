"""Summary and compatibility views over the analysis artifacts."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from eth_utils.crypto import keccak

from schemas.contract_analysis import (
    ContractClassification,
    ControlModel,
    PausabilityAnalysis,
    RoleDefinition,
    SemanticControlAnalysis,
    TimelockAnalysis,
    TrackingHint,
    UpgradeabilityAnalysis,
)

from .constants import (
    STANDARD_EVENTS,
    STANDARD_SIGNATURES,
)
from .shared import (
    _all_modifiers,
    _all_state_variables,
    _call_or_value,
    _contract_events,
    _contract_functions,
    _contract_signatures,
    _declaring_contract_name,
    _dedupe_strings,
    _entry_points,
    _source_evidence,
)

_SENSITIVE_SINK_KINDS = frozenset({"state_write", "external_call", "delegatecall", "contract_creation", "selfdestruct"})


def _tree_has_caller_or_delegated_authority(tree: dict | None) -> bool:
    """True iff some leaf is ``caller_authority`` or ``delegated_authority``."""
    if not isinstance(tree, dict):
        return False
    if tree.get("op") == "LEAF":
        leaf = tree.get("leaf") or {}
        return leaf.get("authority_role") in ("caller_authority", "delegated_authority")
    for child in tree.get("children") or []:
        if _tree_has_caller_or_delegated_authority(child):
            return True
    return False


def _function_has_sensitive_sink(effect_info: dict | None) -> bool:
    if not isinstance(effect_info, dict):
        return False
    for sink in effect_info.get("sinks") or []:
        if isinstance(sink, dict) and sink.get("kind") in _SENSITIVE_SINK_KINDS:
            return True
    return False


def _operand_is_role_key(leaf: Mapping[str, Any] | None, operand: Mapping[str, Any]) -> bool:
    """True iff *operand* is a key of a mapping the leaf tests membership in with an empty member path: the only
    shape proving a bytes32 constant is a role (``_roles[ROLE][account]``). A member path means a struct base (an
    ERC-7201 pointer); both are bytes32 constants, but the lowering shape separates them.

    Cross-contract ``registry.hasRole(ROLE, msg.sender)`` is not admitted: the recorded callee signature is the caller's
    declared interface, not the deployed ABI, and argument position adds no witness. Those roles are not determined.
    """
    if not isinstance(leaf, Mapping):
        return False
    if operand.get("member_path"):
        return False
    if leaf.get("kind") != "membership":
        return False
    descriptor = leaf.get("set_descriptor")
    return isinstance(descriptor, Mapping) and descriptor.get("kind") == "mapping_membership"


def _role_names_from_tree(tree: dict | None, state_vars_by_name: Mapping[str, Any] | None = None) -> set[str]:
    if not isinstance(tree, dict):
        return set()
    roles: set[str] = set()

    def visit(node: Any) -> None:
        if not isinstance(node, dict):
            return
        if node.get("op") == "LEAF":
            leaf = node.get("leaf") or {}
            if not isinstance(leaf, dict):
                return
            if leaf.get("authority_role") in {"caller_authority", "delegated_authority"}:
                for operand in leaf.get("operands") or []:
                    if not isinstance(operand, dict) or operand.get("source") != "state_variable":
                        continue
                    # Key-ness depends on the operand's position.
                    if not _operand_is_role_key(leaf, operand):
                        continue
                    name = operand.get("state_variable_name")
                    if (
                        isinstance(name, str)
                        and state_vars_by_name is not None
                        and _is_bytes32_constant(state_vars_by_name.get(name))
                    ):
                        roles.add(name)
            return
        for child in node.get("children") or []:
            visit(child)

    visit(tree)
    return roles


def _role_names_from_predicate_trees(
    predicate_trees: Mapping[str, Any] | None,
    state_vars_by_name: Mapping[str, Any] | None = None,
) -> set[str]:
    if not isinstance(predicate_trees, dict):
        return set()
    trees = predicate_trees.get("trees")
    if not isinstance(trees, dict):
        return set()
    roles: set[str] = set()
    for tree in trees.values():
        roles.update(_role_names_from_tree(tree, state_vars_by_name))
    return roles


def _is_bytes32_constant(variable: Any) -> bool:
    return (
        variable is not None
        and str(getattr(variable, "type", "")) == "bytes32"
        and bool(getattr(variable, "is_constant", False))
    )


def _caller_equality_state_vars_from_tree(tree: dict | None) -> set[str]:
    if not isinstance(tree, dict):
        return set()
    out: set[str] = set()

    def visit(node: Any) -> None:
        if not isinstance(node, dict):
            return
        if node.get("op") == "LEAF":
            leaf = node.get("leaf") or {}
            if not isinstance(leaf, dict):
                return
            if leaf.get("kind") != "equality" or leaf.get("authority_role") != "caller_authority":
                return
            operands = [op for op in leaf.get("operands") or [] if isinstance(op, dict)]
            has_caller = any(op.get("source") in {"msg_sender", "tx_origin", "signature_recovery"} for op in operands)
            if not has_caller:
                return
            for operand in operands:
                if operand.get("source") == "state_variable":
                    name = operand.get("state_variable_name")
                    if isinstance(name, str) and name:
                        out.add(name)
            return
        for child in node.get("children") or []:
            visit(child)

    visit(tree)
    return out


def _authority_roles_from_tree(tree: dict | None) -> set[str]:
    if not isinstance(tree, dict):
        return set()
    roles: set[str] = set()

    def visit(node: Any) -> None:
        if not isinstance(node, dict):
            return
        if node.get("op") == "LEAF":
            leaf = node.get("leaf") or {}
            if isinstance(leaf, dict):
                role = leaf.get("authority_role")
                if isinstance(role, str) and role:
                    roles.add(role)
            return
        for child in node.get("children") or []:
            visit(child)

    visit(tree)
    return roles


def _controller_refs_from_tree(tree: dict | None) -> list[str]:
    """Unique state-variable and role operand names referenced by any leaf."""
    if not isinstance(tree, dict):
        return []
    refs: list[str] = []
    seen: set[str] = set()

    def add(name: str | None) -> None:
        if isinstance(name, str) and name and name not in seen:
            seen.add(name)
            refs.append(name)

    def visit(node):
        if not isinstance(node, dict):
            return
        if node.get("op") == "LEAF":
            leaf = node.get("leaf") or {}
            for operand in leaf.get("operands") or []:
                if not isinstance(operand, dict):
                    continue
                if operand.get("source") == "state_variable":
                    add(operand.get("state_variable_name"))
            descriptor = leaf.get("set_descriptor") or {}
            if isinstance(descriptor, dict):
                authority = descriptor.get("authority_contract") or {}
                if isinstance(authority, dict):
                    address_source = authority.get("address_source") or {}
                    if isinstance(address_source, dict) and address_source.get("source") == "state_variable":
                        add(address_source.get("state_variable_name"))
                for key_source in descriptor.get("key_sources") or []:
                    if not isinstance(key_source, dict):
                        continue
                    if key_source.get("source") == "state_variable":
                        add(key_source.get("state_variable_name"))
            return
        for child in node.get("children") or []:
            visit(child)

    visit(tree)
    return refs


def _sink_ids_from_effect_info(effect_info: dict | None) -> list[str]:
    if not isinstance(effect_info, dict):
        return []
    out: list[str] = []
    seen: set[str] = set()
    for sink in effect_info.get("sinks") or []:
        if not isinstance(sink, dict):
            continue
        sid = sink.get("id")
        if isinstance(sid, str) and sid and sid not in seen:
            seen.add(sid)
            out.append(sid)
    return out


def _effect_records_with_label(effects: Mapping[str, Any] | None, label: str) -> list[tuple[str, dict[str, Any]]]:
    if not isinstance(effects, dict):
        return []
    records: list[tuple[str, dict[str, Any]]] = []
    for signature, info in (effects.get("functions") or {}).items():
        if not isinstance(signature, str) or not isinstance(info, dict):
            continue
        if label in (info.get("effect_labels") or []):
            records.append((signature, info))
    return records


_KNOWN_SELECTORS: dict[int, str] = {
    0xA9059CBB: "asset_send",  # transfer(address,uint256)
    0x23B872DD: "asset_pull",  # transferFrom(address,address,uint256)
    0x40C10F19: "mint",  # mint(address,uint256)
    0x42966C68: "burn",  # burn(uint256)
    0x9DC29FAC: "burn",  # burn(address,uint256)
    0x79CC6790: "burn",  # burnFrom(address,uint256)
    0x423F6CEF: "asset_send",  # safeTransfer(address,uint256)
    0x42842E0E: "asset_pull",  # safeTransferFrom(address,address,uint256)
    0xB88D4FDE: "asset_pull",  # safeTransferFrom(address,address,uint256,bytes)
}

_LABEL_TO_FLOW_DIRECTION = {
    "asset_send": "out",
    "asset_pull": "in",
    "mint": "mint",
    "burn": "burn",
}

# Canonical selectors of standard access-control entry points: a compatible contract can't rename them, and bespoke
# schemes fall through (false negatives only). Role membership is matched here rather than by the predicate post-pass
# because caller-keyed data maps look like ACLs (``sendCompose``). Ownership stays in the post-pass.
_ACCESS_CONTROL_SELECTORS: dict[str, str] = {
    "0x2f2ff15d": "role_management",  # grantRole(bytes32,address)                   OZ AccessControl
    "0xd547741f": "role_management",  # revokeRole(bytes32,address)                  OZ AccessControl
    "0x67aff484": "role_management",  # setUserRole(address,uint8,bool)              Solmate RolesAuthority
    "0x7d40583d": "role_management",  # setRoleCapability(uint8,address,bytes4,bool) Solmate RolesAuthority
    "0xc6b0263e": "role_management",  # setPublicCapability(address,bytes4,bool)     Solmate RolesAuthority
    "0x7a9e5e4b": "authority_update",  # setAuthority(address)                       Solmate Auth / DSAuth
}


def _label_for_selector(selector: object) -> str | None:
    if not isinstance(selector, str):
        return None
    normalized = selector.lower()
    if not normalized.startswith("0x") or len(normalized) != 10:
        return None
    try:
        selector_value = int(normalized, 16)
    except ValueError:
        return None
    return _KNOWN_SELECTORS.get(selector_value)


def _selector_for_signature(signature: str | None) -> str | None:
    if not isinstance(signature, str) or "(" not in signature or not signature.endswith(")"):
        return None
    return "0x" + keccak(text=signature)[:4].hex()


def _access_control_label(function) -> str | None:
    """Label for a standard access-control entry point by canonical selector, else None."""
    try:
        signature = function.solidity_signature
    except (ValueError, AttributeError):
        return None
    selector = _selector_for_signature(signature)
    return _ACCESS_CONTROL_SELECTORS.get(selector) if selector else None


def _callee_signature_from_ir(call_ir: Any) -> str | None:
    callee = getattr(call_ir, "function", None)
    for attr in ("full_name", "signature_str"):
        value = getattr(callee, attr, None)
        if callable(value):
            value = value()
        if isinstance(value, str) and "(" in value and value.endswith(")"):
            return value
    value = getattr(call_ir, "function_name", None)
    if isinstance(value, str) and "(" in value and value.endswith(")"):
        return value
    return None


def _labels_from_external_call_sinks(graph_entry: dict | None) -> set[str]:
    labels: set[str] = set()
    if not graph_entry:
        return labels
    for sink in graph_entry.get("sinks") or []:
        if not isinstance(sink, dict) or sink.get("kind") != "external_call":
            continue
        label = _label_for_selector(sink.get("selector"))
        if label:
            labels.add(label)
    return labels


def _function_has_low_level_value_call(function) -> bool:
    """Whether the function or its callees send ETH via ``.call{value:}``."""
    visited: set[int] = set()

    def _check(fn) -> bool:
        fn_id = id(fn)
        if fn_id in visited:
            return False
        visited.add(fn_id)
        for node in fn.nodes:
            for ir in node.irs:
                ir_str = str(ir)
                if "LOW_LEVEL_CALL" in ir_str and "value:" in ir_str:
                    return True
        for call in _call_or_value(fn, "all_internal_calls"):
            callee = getattr(call, "function", call) if not callable(call) else call
            if hasattr(callee, "nodes") and _check(callee):
                return True
        return False

    return _check(function)


def _detect_encoded_selectors(function) -> set[str]:
    """Known ERC-20 selectors in ``abi.encodeWithSelector`` calls."""
    labels: set[str] = set()
    visited: set[int] = set()

    def _check(fn) -> None:
        fn_id = id(fn)
        if fn_id in visited:
            return
        visited.add(fn_id)
        for node in fn.nodes:
            for ir in node.irs:
                ir_str = str(ir)
                if "abi.encodeWithSelector" not in ir_str:
                    continue
                paren_start = ir_str.rfind("(")
                if paren_start < 0:
                    continue
                args = ir_str[paren_start + 1 :].rstrip(")")
                first_arg = args.split(",")[0].strip()
                try:
                    selector_val = int(first_arg)
                    label = _KNOWN_SELECTORS.get(selector_val)
                    if label:
                        labels.add(label)
                except (ValueError, TypeError):
                    pass
        for call in _call_or_value(fn, "all_internal_calls"):
            callee = getattr(call, "function", call) if not callable(call) else call
            if hasattr(callee, "nodes"):
                _check(callee)

    _check(function)
    return labels


def _effect_labels(function, graph_entry: dict | None) -> list[str]:
    """The fact-tier labels (value-flow selectors, low-level value moves, access-control selectors, sink
    capabilities).

    Semantic labels come from claims via ``project_effect_labels``.
    """
    labels: set[str] = set()
    sink_kinds = set(graph_entry.get("sink_kinds", [])) if graph_entry else set()

    if _function_has_low_level_value_call(function):
        labels.add("asset_send")

    labels.update(_detect_encoded_selectors(function))
    labels.update(_labels_from_external_call_sinks(graph_entry))

    access_control = _access_control_label(function)
    if access_control:
        labels.add(access_control)

    if sink_kinds.intersection({"contract_creation"}):
        labels.add("contract_deployment")
    if sink_kinds.intersection({"delegatecall"}):
        labels.add("delegatecall_execution")
    if sink_kinds.intersection({"selfdestruct"}):
        labels.add("selfdestruct_capability")

    if labels.intersection({"asset_pull", "asset_send", "arbitrary_external_call", "mint", "burn"}):
        labels.discard("external_contract_call")

    return _dedupe_strings(list(labels))


def _resolve_cast_head(head: Any, def_by_id: dict[int, Any]) -> Any:
    """Follow ``TypeConversion`` casts from a temporary to the variable it aliases
    (``IERC20(address(eETH)).safeTransferFrom`` gives ``TMP_n``). Casts only (non-SSA assignments could pick a
    branch), and only while the value is a temporary. Elements and computed values are returned unchanged.
    """
    from slither.slithir.variables.temporary import TemporaryVariable

    seen: set[int] = set()
    value = head
    while isinstance(value, TemporaryVariable) and id(value) not in seen:
        seen.add(id(value))
        ir = def_by_id.get(id(value))
        if ir is None or type(ir).__name__ != "TypeConversion":
            break
        value = getattr(ir, "variable", None)
    return value


def _function_ir_def_map(function: Any) -> dict[int, Any]:
    """Non-SSA ``{id(lvalue) -> defining IR}`` over ``function`` and its callees (this walk reads ``node.irs``, so
    SSA maps don't apply).
    """
    out: dict[int, Any] = {}
    seen: set[int] = set()

    def visit(fn: Any) -> None:
        if fn is None or id(fn) in seen:
            return
        seen.add(id(fn))
        for node in getattr(fn, "nodes", []) or []:
            for ir in getattr(node, "irs", []) or []:
                lvalue = getattr(ir, "lvalue", None)
                if lvalue is not None:
                    out[id(lvalue)] = ir
                if type(ir).__name__ in ("InternalCall", "LibraryCall"):
                    visit(getattr(ir, "function", None))

    visit(function)
    return out


def _extract_value_flows(function) -> list[dict]:
    """Value flows from standard selectors: ``{direction, token_var, token_type, method, is_parameter}``.

    ``token_var`` is the caller-selectable address (the token for ERC-20, the recipient for native sends);
    ``is_parameter`` only for this function's own parameters. Read from IR objects, never ``repr``.
    """
    flows: list[dict] = []
    parameters = {id(p) for p in function.parameters}
    def_by_id = _function_ir_def_map(function)

    for _ct, call_ir in function.all_high_level_calls():
        destination = getattr(call_ir, "destination", None)
        if destination is None:
            continue
        # Resolve to the aliased state var so ``token_var`` isn't ``TMP_n``.
        destination = _resolve_cast_head(destination, def_by_id)
        var_name = getattr(destination, "name", None)
        if not isinstance(var_name, str) or not var_name:
            continue
        var_type = str(getattr(destination, "type", "") or "")

        signature = _callee_signature_from_ir(call_ir)
        selector = _selector_for_signature(signature)
        label = _label_for_selector(selector)
        direction = _LABEL_TO_FLOW_DIRECTION.get(label or "")
        if not direction:
            continue
        flows.append(
            {
                "direction": direction,
                "token_var": var_name,
                "token_type": var_type or None,
                "method": signature or selector,
                "is_parameter": id(destination) in parameters,
            }
        )

    visited: set[int] = set()

    def _check_low_level(fn, is_entry: bool) -> None:
        fn_id = id(fn)
        if fn_id in visited:
            return
        visited.add(fn_id)
        for node in fn.nodes:
            for ir in node.irs:
                if type(ir).__name__ != "LowLevelCall" or getattr(ir, "call_value", None) is None:
                    continue
                # A helper's destination is a callee formal, meaningless to the entry's caller.
                dest = getattr(ir, "destination", None) if is_entry else None
                recipient = getattr(dest, "name", None) if dest is not None and id(dest) in parameters else None
                flows.append(
                    {
                        "direction": "eth_out",
                        "token_var": recipient,
                        "token_type": "ETH",
                        "method": "call{value}",
                        "is_parameter": recipient is not None,
                    }
                )
                return
        for call in _call_or_value(fn, "all_internal_calls"):
            callee = getattr(call, "function", call) if not callable(call) else call
            if hasattr(callee, "nodes"):
                _check_low_level(callee, False)

    _check_low_level(function, True)

    return flows


def _action_summary(effect_labels: list[str], effect_targets: list[str]) -> str:
    labels = set(effect_labels)

    if {"asset_pull", "mint"}.issubset(labels):
        return "Pulls assets into the contract and mints contract balances or shares."
    if {"burn", "asset_send"}.issubset(labels):
        return "Burns contract balances or shares and sends assets out of the contract."
    if "arbitrary_external_call" in labels:
        return "Executes arbitrary external calldata from the contract."
    if "external_contract_call" in labels:
        return "Calls an external contract from the contract context."
    if "authority_update" in labels:
        return "Updates the authority contract used for permission checks."
    if "ownership_transfer" in labels:
        return "Transfers contract ownership."
    if "hook_update" in labels:
        return "Updates hook configuration that can affect later contract behavior."
    if "pause_toggle" in labels:
        return "Changes the contract pause state."
    if "implementation_update" in labels:
        return "Changes implementation or upgrade control state."
    if "role_management" in labels:
        return "Changes role-based permissions."
    if "timelock_operation" in labels:
        return "Schedules, executes, or cancels timelocked operations."
    if "contract_deployment" in labels:
        return "Deploys a new contract instance."
    if "delegatecall_execution" in labels:
        return "Executes delegatecall-controlled logic."
    if "selfdestruct_capability" in labels:
        return "Can destroy the contract."
    if "asset_pull" in labels:
        return "Pulls assets into the contract."
    if "asset_send" in labels:
        return "Sends assets out of the contract."
    if "mint" in labels:
        return "Mints contract balances or shares."
    if "burn" in labels:
        return "Burns contract balances or shares."
    if effect_targets:
        return f"Writes or calls into: {', '.join(effect_targets)}."
    return "Performs a contract action."


def _detect_contract_classification(
    contract,
    project_dir: Path,
    effects: Mapping[str, Any] | None = None,
) -> ContractClassification:
    standards = set()
    erc_detector = getattr(contract, "ercs", None)
    if callable(erc_detector):
        erc_values = erc_detector()
        if isinstance(erc_values, (list, set, tuple)):
            standards.update(str(value) for value in erc_values)

    signatures = _contract_signatures(contract)
    events = _contract_events(contract)
    for standard, expected_signatures in STANDARD_SIGNATURES.items():
        if expected_signatures.issubset(signatures) and STANDARD_EVENTS[standard].issubset(events):
            standards.add(standard)

    functions_by_signature = {
        getattr(function, "full_name", function.name): function for function in _entry_points(contract)
    }
    # ``is_factory`` comes from the effects artifact, so a degraded one leaves it unknown rather than false. The other
    # fields are IR-derived and run on every parse, so ``standards: []`` is a real absence.
    effects_available = isinstance(effects, Mapping) and isinstance(effects.get("functions"), Mapping)
    factory_functions = []
    evidence = []
    if effects_available and effects is not None:
        for signature, info in (effects.get("functions") or {}).items():
            if not isinstance(signature, str) or not isinstance(info, dict):
                continue
            has_creation_sink = any(
                isinstance(sink, dict) and sink.get("kind") == "contract_creation" for sink in info.get("sinks") or []
            )
            if not has_creation_sink:
                continue
            factory_functions.append(signature)
            function = functions_by_signature.get(signature)
            if function is not None:
                evidence.append(_source_evidence(function, project_dir))

    standards_list = sorted(standards)
    return {
        "standards": standards_list,
        "is_erc20": "ERC20" in standards,
        "is_erc721": "ERC721" in standards,
        "is_erc1155": "ERC1155" in standards,
        "is_nft": "ERC721" in standards or "ERC1155" in standards,
        "is_factory": bool(factory_functions) if effects_available else None,
        "factory_functions": sorted(factory_functions) if effects_available else None,
        "evidence": evidence,
    }


def _build_semantic_control_summary(
    contract,
    project_dir: Path,
    predicate_trees: Mapping[str, Any] | None,
    effects: Mapping[str, Any] | None,
) -> SemanticControlAnalysis:
    """Semantic control summary.

    A function is included iff its tree has a caller/delegated-authority leaf or its effects carry a sensitive sink;
    role definitions come from leaf role keys.
    """
    state_variables = _all_state_variables(contract)
    state_vars_by_name = {getattr(variable, "name", ""): variable for variable in state_variables}
    functions = _entry_points(contract)
    semantic_trees = (predicate_trees or {}).get("trees") or {}
    effects_functions = (effects or {}).get("functions") or {}

    owner_variables = sorted(
        {
            name
            for tree in semantic_trees.values()
            for name in _caller_equality_state_vars_from_tree(tree if isinstance(tree, dict) else None)
        }
    )
    admin_variables: list[str] = []
    role_definitions = []
    for name in sorted(_role_names_from_predicate_trees(predicate_trees, state_vars_by_name)):
        variable = state_vars_by_name.get(name)
        if variable is not None:
            role_definitions.append(
                {
                    "role": name,
                    "declared_in": _declaring_contract_name(variable, contract.name),
                    "evidence": [_source_evidence(variable, project_dir)],
                }
            )
        else:
            role_definitions.append({"role": name, "declared_in": contract.name, "evidence": []})

    semantic_functions = []
    for function in functions:
        function_signature = getattr(function, "full_name", getattr(function, "name", ""))
        tree = semantic_trees.get(function_signature)
        effect_info = effects_functions.get(function_signature)

        has_caller_authority_leaf = _tree_has_caller_or_delegated_authority(tree)
        has_sensitive_sink = _function_has_sensitive_sink(effect_info)
        # Pause/reentrancy/business/time-only trees don't admit a function.
        if not (has_caller_authority_leaf or has_sensitive_sink):
            continue

        # Missing effects leave these empty rather than inferring them another way.
        if isinstance(effect_info, dict):
            effects_list = list(effect_info.get("effects") or [])
            effect_targets = list(effect_info.get("effect_targets") or [])
            effect_labels = list(effect_info.get("effect_labels") or [])
            action_summary = effect_info.get("action_summary") or _action_summary(effect_labels, effect_targets)
        else:
            effects_list = []
            effect_targets = []
            effect_labels = []
            action_summary = _action_summary(effect_labels, effect_targets)

        leaf_controller_refs = _controller_refs_from_tree(tree) if isinstance(tree, dict) else []
        sink_ids = _sink_ids_from_effect_info(effect_info)

        entry: dict = {
            "contract": _declaring_contract_name(function, contract.name),
            "function": function_signature,
            "visibility": getattr(function, "visibility", "unknown"),
            "guards": [],
            "guard_kinds": [],
            "controller_refs": _dedupe_strings(leaf_controller_refs),
            "sink_ids": sink_ids,
            "effects": effects_list,
            "effect_targets": effect_targets,
            "effect_labels": effect_labels,
            "value_flows": _extract_value_flows(function),
            "action_summary": action_summary,
        }
        semantic_functions.append(entry)

    authority_roles = {
        role
        for tree in semantic_trees.values()
        for role in _authority_roles_from_tree(tree if isinstance(tree, dict) else None)
    }
    has_role_identifiers = bool(_role_names_from_predicate_trees(predicate_trees, state_vars_by_name))
    pattern = "unknown"
    if has_role_identifiers or "delegated_authority" in authority_roles:
        pattern = "role_control"
    elif owner_variables:
        pattern = "ownable"
    elif semantic_functions:
        pattern = "custom"

    result: SemanticControlAnalysis = {
        "pattern": pattern,
        "owner_variables": _dedupe_strings(owner_variables),
        "admin_variables": _dedupe_strings(admin_variables),
        "role_definitions": sorted(role_definitions, key=lambda role: role["role"]),
        "semantic_functions": sorted(semantic_functions, key=lambda item: item["function"]),
        "current_holders": {
            "status": "unknown_static_only",
        },
    }
    return result


def _detect_upgradeability(
    contract,
    project_dir: Path,
    effects: Mapping[str, Any] | None = None,
) -> UpgradeabilityAnalysis:
    update_records = _effect_records_with_label(effects, "implementation_update")
    functions_by_signature = {
        getattr(function, "full_name", function.name): function for function in _contract_functions(contract)
    }

    admin_paths = [signature for signature, _info in update_records]
    implementation_slots: list[str] = []
    evidence = []
    for signature, info in update_records:
        for sink in info.get("sinks") or []:
            if isinstance(sink, dict) and sink.get("kind") == "state_write":
                target = sink.get("target")
                if isinstance(target, str) and target:
                    implementation_slots.append(target)
        function = functions_by_signature.get(signature)
        if function is not None:
            evidence.append(_source_evidence(function, project_dir))

    is_proxy_shell = bool(getattr(contract, "is_upgradeable_proxy", False))
    pattern = "custom" if is_proxy_shell or admin_paths else "none"

    return {
        "is_upgradeable": bool(admin_paths) or is_proxy_shell,
        "is_upgradeable_proxy": is_proxy_shell,
        "pattern": pattern,
        "upgradeable_version": getattr(contract, "upgradeable_version", None),
        "implementation_slots": _dedupe_strings(implementation_slots),
        "admin_paths": _dedupe_strings(admin_paths),
        "evidence": evidence,
    }


def _claims_plane_ran(effects: Mapping[str, Any] | None) -> bool:
    """Whether the claims matcher completed on this artifact.

    ``core`` runs effects and claims in separate try blocks, so a full ``functions`` map only proves effects ran. The
    ``claims`` key discriminates: ``attach_claims_to_effects`` sets it on every record (``[]`` when none) and
    ``build_effects`` never does. No functions is not determined. This proves completion, not that the matcher could see
    (see :func:`_predicate_trees_plane_ran`).
    """
    functions = (effects or {}).get("functions")
    if not isinstance(functions, Mapping):
        return False
    return any(isinstance(record, Mapping) and "claims" in record for record in functions.values())


def _predicate_trees_plane_ran(predicate_trees: Mapping[str, Any] | None) -> bool:
    """Whether the predicate-tree stage completed.

    It is the claims matcher's input and also runs the reentrancy/pause pass, so its failure blinds both pause detectors
    while every record still gets a ``claims`` key. The ``trees`` key discriminates (``{}`` is a real empty result; the
    degraded stub has only ``error``). ``None`` is not determined.
    """
    if not isinstance(predicate_trees, Mapping):
        return False
    if "error" in predicate_trees:
        return False
    return isinstance(predicate_trees.get("trees"), Mapping)


_PAUSE_CLAIM_POLARITY = {"pause.set": "pause", "pause.unset": "unpause"}


def _pause_claims(effects: Mapping[str, Any] | None) -> tuple[set[str], set[str], set[str]]:
    """``(pause_functions, unpause_functions, flag_paths)`` from ``pause.set``/``pause.unset`` claims.

    PauseAnalyzer only sees top-level scalar flags and misses struct-member (Veda) and ERC-7201 (EtherFi/OZ-v5) latches;
    the claims matcher resolves both. EigenLayer bitmap ``pause(uint256)`` writes from a parameter, so it correctly
    mints no claim.
    """
    functions = (effects or {}).get("functions")
    if not isinstance(functions, Mapping):
        return set(), set(), set()
    pause_functions: set[str] = set()
    unpause_functions: set[str] = set()
    flags: set[str] = set()
    for signature, info in functions.items():
        if not isinstance(signature, str) or not isinstance(info, Mapping):
            continue
        for claim in info.get("claims") or []:
            if not isinstance(claim, Mapping):
                continue
            polarity = _PAUSE_CLAIM_POLARITY.get(str(claim.get("claim_id")))
            if polarity is None:
                continue
            (pause_functions if polarity == "pause" else unpause_functions).add(signature)
            witness = claim.get("witness")
            for flag in (witness or {}).get("flags") or [] if isinstance(witness, Mapping) else []:
                if not isinstance(flag, Mapping):
                    continue
                variable = flag.get("var")
                if not isinstance(variable, str) or not variable:
                    continue
                member = flag.get("member")
                flags.add(f"{variable}.{member}" if isinstance(member, str) and member else variable)
    return pause_functions, unpause_functions, flags


def _detect_pausability(
    contract,
    project_dir: Path,
    pause_info: Mapping[str, Any] | None = None,
    effects: Mapping[str, Any] | None = None,
    predicate_trees: Mapping[str, Any] | None = None,
) -> PausabilityAnalysis:
    """Pausability from the structural ``PauseInfo`` and the pause claims.

    Gating modifiers read a pause var; toggles are pause or unpause by the value written, both when ambiguous.
    ``is_pausable`` is ``False`` only when nothing was found and both :func:`_claims_plane_ran` and
    :func:`_predicate_trees_plane_ran` hold; otherwise ``None``.
    """
    info = pause_info or {}
    pause_state_vars: list[str] = list(info.get("pause_state_vars") or [])
    toggle_functions: list[str] = list(info.get("pause_toggle_functions") or [])

    pause_var_set = set(pause_state_vars)
    pause_functions: set[str] = set()
    unpause_functions: set[str] = set()

    if pause_var_set:
        functions_by_full = {}
        for fn in getattr(contract, "functions", []) or []:
            full = getattr(fn, "full_name", None) or getattr(fn, "name", None)
            if isinstance(full, str):
                functions_by_full[full] = fn

        for full_name in toggle_functions:
            fn = functions_by_full.get(full_name)
            if fn is None:
                pause_functions.add(full_name)
                continue
            polarity = _classify_pause_toggle_polarity(fn, pause_var_set)
            if polarity == "pause":
                pause_functions.add(full_name)
            elif polarity == "unpause":
                unpause_functions.add(full_name)
            else:
                # Parameter-driven or branched: both.
                pause_functions.add(full_name)
                unpause_functions.add(full_name)

    claim_pause, claim_unpause, claim_flags = _pause_claims(effects)
    pause_functions |= claim_pause
    unpause_functions |= claim_unpause

    modifiers = _all_modifiers(contract)
    gating_modifiers: list[str] = []
    evidence = []
    # Claim flags may be dotted paths; modifiers read the base variable.
    gate_var_set = pause_var_set | {path.split(".", 1)[0] for path in claim_flags}
    if gate_var_set:
        for modifier in modifiers:
            read_names = {getattr(v, "name", "") for v in getattr(modifier, "state_variables_read", []) or []}
            if read_names & gate_var_set:
                gating_modifiers.append(modifier.name)
                evidence.append(_source_evidence(modifier, project_dir))

    if pause_functions or unpause_functions or gating_modifiers or pause_state_vars:
        is_pausable: bool | None = True
    elif _claims_plane_ran(effects) and _predicate_trees_plane_ran(predicate_trees):
        is_pausable = False
    else:
        # Both checks are needed: without claims, ``False`` denies latches only claims can see; without trees, one stage
        # failure makes every pausable contract ``False``.
        is_pausable = None

    return {
        "is_pausable": is_pausable,
        "pause_functions": sorted(pause_functions),
        "unpause_functions": sorted(unpause_functions),
        "gating_modifiers": sorted(gating_modifiers),
        # Claim flags keep their member path, the only handle on which member is the latch.
        "pause_variables": sorted(set(pause_state_vars) | claim_flags),
        "authorized_roles": [],
        "evidence": evidence,
    }


def _classify_pause_toggle_polarity(function, pause_vars: set[str]) -> str:
    """``"pause"`` if ``function`` writes a pause var with a true-ish constant, ``"unpause"`` if false-ish, ``""``
    otherwise.
    """
    polarities: set[str] = set()
    for node in getattr(function, "nodes", []) or []:
        for ir in getattr(node, "irs", []) or []:
            op = type(ir).__name__
            if op != "Assignment":
                continue
            lvalue = getattr(ir, "lvalue", None)
            target = getattr(lvalue, "name", None)
            if isinstance(target, str):
                parts = target.rsplit("_", 1)
                if len(parts) == 2 and parts[1].isdigit():
                    target = parts[0]
            if target not in pause_vars:
                continue
            rvalue = getattr(ir, "rvalue", None)
            rtext = getattr(rvalue, "name", None) or getattr(rvalue, "value", None) or str(rvalue or "")
            rtext_lower = str(rtext).strip().lower()
            if rtext_lower in ("true", "1"):
                polarities.add("pause")
            elif rtext_lower in ("false", "0"):
                polarities.add("unpause")
    if polarities == {"pause"}:
        return "pause"
    if polarities == {"unpause"}:
        return "unpause"
    return ""


_TIMELOCK_QUEUE_CLAIMS = frozenset({"timelock.schedule"})
_TIMELOCK_EXECUTE_CLAIMS = frozenset({"timelock.execute"})
_TIMELOCK_CLAIMS = frozenset({"timelock.schedule", "timelock.execute", "timelock.cancel", "timelock.set_delay"})

# ``now`` is the pre-0.7 spelling.
_TIME_SOURCE_NAMES = frozenset({"block.timestamp", "now", "block.number"})

# OZ needs 3 (``execute`` -> ``_beforeCall`` -> ``isOperationReady``).
_TIMELOCK_CALL_DEPTH = 4


def _timelock_claim_functions(effects: Mapping[str, Any] | None) -> dict[str, set[str]]:
    """``claim_id -> {signature}`` for ``timelock.*`` claims (the standard OZ TimelockController half)."""
    out: dict[str, set[str]] = {}
    functions = (effects or {}).get("functions")
    if not isinstance(functions, Mapping):
        return out
    for signature, info in functions.items():
        if not isinstance(signature, str) or not isinstance(info, Mapping):
            continue
        for claim in info.get("claims") or []:
            if not isinstance(claim, Mapping):
                continue
            claim_id = str(claim.get("claim_id"))
            if claim_id in _TIMELOCK_CLAIMS:
                out.setdefault(claim_id, set()).add(signature)
    return out


def _arbitrary_execution_functions(effects: Mapping[str, Any] | None) -> set[str]:
    """Signatures with ``exec.arbitrary``: separates a timelock (queue any action) from a cooldown (one hard-coded
    operation).
    """
    out: set[str] = set()
    functions = (effects or {}).get("functions")
    if not isinstance(functions, Mapping):
        return out
    for signature, info in functions.items():
        if not isinstance(signature, str) or not isinstance(info, Mapping):
            continue
        for claim in info.get("claims") or []:
            if isinstance(claim, Mapping) and str(claim.get("claim_id")) == "exec.arbitrary":
                out.add(signature)
    return out


def _ir_reads(ir: Any) -> set[str]:
    return {str(value) for value in (getattr(ir, "read", []) or [])}


def _transitive_irs(function: Any, depth: int = _TIMELOCK_CALL_DEPTH) -> list[Any]:
    """Every IR in ``function`` and, recursively, its callees and modifiers; the timelock halves live in helpers.

    Cycle-safe, depth-bounded.
    """
    seen: set[int] = set()
    out: list[Any] = []

    def walk(container: Any, remaining: int) -> None:
        if container is None or remaining < 0 or id(container) in seen:
            return
        seen.add(id(container))
        for node in getattr(container, "nodes", []) or []:
            for ir in list(getattr(node, "irs_ssa", None) or []) + list(getattr(node, "irs", []) or []):
                out.append(ir)
                callee = getattr(ir, "function", None)
                if callee is not None and type(ir).__name__ in ("InternalCall", "LibraryCall"):
                    walk(callee, remaining - 1)
        for modifier in getattr(container, "modifiers", []) or []:
            walk(modifier, remaining - 1)

    walk(function, depth)
    return out


def _derivation_closure(irs: list[Any], seeds: set[str]) -> set[str]:
    reached = set(seeds)
    changed = True
    while changed:
        changed = False
        for ir in irs:
            lvalue = getattr(ir, "lvalue", None)
            if lvalue is None:
                continue
            name = str(lvalue)
            if name in reached:
                continue
            if _ir_reads(ir) & reached:
                reached.add(name)
                changed = True
    return reached


def _state_var_names(contract) -> dict[str, Any]:
    return {getattr(v, "name", ""): v for v in _all_state_variables(contract)}


def _timestamp_registry_writes(contract) -> dict[str, set[str]]:
    """``registry_var -> {state vars in its derivation}``: a variable written with a value the clock flows into
    ("matures at T"), plus stored inputs like the delay.
    """
    state_vars = _state_var_names(contract)
    registries: dict[str, set[str]] = {}
    for function in getattr(contract, "functions", []) or []:
        if getattr(function, "is_constructor", False):
            continue
        irs = _transitive_irs(function)
        time_seeds = {name for ir in irs for name in _ir_reads(ir) if name in _TIME_SOURCE_NAMES}
        if not time_seeds:
            continue
        derived = _derivation_closure(irs, time_seeds)
        for ir in irs:
            if type(ir).__name__ != "Assignment":
                continue
            if not (_ir_reads(ir) & derived):
                continue
            target = _base_written_state_var(ir, state_vars)
            if target is None:
                continue
            contributors = {
                name
                for ir2 in irs
                if str(getattr(ir2, "lvalue", "")) in derived
                for name in _ir_reads(ir2)
                if name in state_vars and name != target
            }
            registries.setdefault(target, set()).update(contributors)
    return registries


def _base_written_state_var(ir: Any, state_vars: Mapping[str, Any]) -> str | None:
    """The state variable an Assignment writes (through references), or ``None`` for locals."""
    lvalue = getattr(ir, "lvalue", None)
    for candidate in (lvalue, getattr(lvalue, "points_to_origin", None), getattr(lvalue, "points_to", None)):
        name = getattr(candidate, "name", None)
        if isinstance(name, str) and name in state_vars:
            return name
    return None


def _maturity_gate_functions(contract, registries: set[str]) -> dict[str, set[str]]:
    """``registry_var -> {signature}`` for entry points that revert unless the registry value matured.

    The require and comparison may sit in different helpers.
    """
    out: dict[str, set[str]] = {}
    for function in _entry_points(contract):
        if getattr(function, "is_constructor", False):
            continue
        irs = _transitive_irs(function)
        if not any(_ir_is_require_or_revert_like(ir) for ir in irs):
            continue
        reads_clock = any(_ir_reads(ir) & _TIME_SOURCE_NAMES for ir in irs)
        if not reads_clock:
            continue
        for ir in irs:
            if type(ir).__name__ != "Binary":
                continue
            names = _ir_reads(ir)
            if not (names & _TIME_SOURCE_NAMES) and not _binary_compares_clock(ir, irs):
                continue
            for registry in registries:
                if registry in _registry_sources(irs, names):
                    out.setdefault(registry, set()).add(
                        getattr(function, "full_name", None) or getattr(function, "name", "")
                    )
    return out


def _binary_compares_clock(ir: Any, irs: list[Any]) -> bool:
    sources = _backward_sources(irs, _ir_reads(ir))
    return bool(sources & _TIME_SOURCE_NAMES)


def _registry_sources(irs: list[Any], names: set[str]) -> set[str]:
    return _backward_sources(irs, names)


def _backward_sources(irs: list[Any], names: set[str]) -> set[str]:
    defs: dict[str, set[str]] = {}
    for ir in irs:
        lvalue = getattr(ir, "lvalue", None)
        if lvalue is None:
            continue
        defs.setdefault(str(lvalue), set()).update(_ir_reads(ir))
    reached = set(names)
    work = list(names)
    while work:
        current = work.pop()
        for source in defs.get(current, ()):
            if source not in reached:
                reached.add(source)
                work.append(source)
    return reached


def _ir_is_require_or_revert_like(ir: Any) -> bool:
    if type(ir).__name__ != "SolidityCall":
        return False
    function = getattr(ir, "function", None)
    name = getattr(function, "name", None) or str(function or "")
    return name.startswith("require(") or name.startswith("revert") or name == "assert(bool)"


def _timelock_delay_variables(contract, registries: Mapping[str, set[str]], queue_functions: set[str]) -> set[str]:
    """Where the delay value lives, for the live half: state vars flowing into the maturity write, and mutable
    integers the queue path reads (OZ ``_minDelay``). Recall-generous: a pointer, never a value. Constants and
    mappings excluded.
    """
    state_vars = _state_var_names(contract)

    def is_delay_shaped(name: str) -> bool:
        variable = state_vars.get(name)
        if variable is None or getattr(variable, "is_constant", False) or getattr(variable, "is_immutable", False):
            return False
        return str(getattr(variable, "type", "")).startswith(("uint", "int"))

    out = {name for contributors in registries.values() for name in contributors if is_delay_shaped(name)}
    for function in getattr(contract, "functions", []) or []:
        full_name = getattr(function, "full_name", None) or getattr(function, "name", "")
        if full_name not in queue_functions:
            continue
        for ir in _transitive_irs(function):
            out |= {name for name in _ir_reads(ir) if is_delay_shaped(name)}
    return out


def _detect_timelock(
    contract,
    project_dir: Path,
    role_definitions: list[RoleDefinition],
    effects: Mapping[str, Any] | None = None,
) -> TimelockAnalysis:
    """Prove from source alone that this contract is a timelock.

    Structurally: a state variable written from the clock (queue) and another entry point reverting until it matures
    (execute), both found transitively. That pair also matches cooldowns, blacklist expiries, withdrawal delays and rate
    limiters, so the maturity-gated function must also carry ``exec.arbitrary``: a timelock delays a caller-chosen
    action. ``pattern`` is ``oz_timelock`` for the published ABI, ``custom`` for structure only.

    The delay is never read or defaulted here (no chain access); a defaulted delay would fabricate protective credit.
    ``delay`` is ``None`` and ``delay_source`` ``"not_read"``; ``delay_variables`` says where it lives.

    ``has_timelock`` is ``False`` only when the IR and the claims plane were both available; otherwise ``None``, since
    ``_determine_control_model`` would drop ``governance`` on a false negative.
    """
    functions = list(getattr(contract, "functions", []) or [])

    if not functions or not _claims_plane_ran(effects):
        return {
            "has_timelock": None,
            "pattern": "unknown",
            "delay": None,
            "delay_source": "not_read",
            "delay_variables": [],
            "queue_execute_functions": [],
            "authorized_roles": [],
            "evidence": [],
        }

    claims = _timelock_claim_functions(effects)
    registries = _timestamp_registry_writes(contract)
    maturity = _maturity_gate_functions(contract, set(registries))
    proven_registries = {name for name in registries if maturity.get(name)}

    queue_functions: set[str] = set()
    execute_functions: set[str] = set()
    for registry in proven_registries:
        execute_functions |= maturity.get(registry, set())
    for function in _entry_points(contract):
        full_name = getattr(function, "full_name", None) or getattr(function, "name", "")
        if full_name in execute_functions:
            continue
        state_vars = _state_var_names(contract)
        irs = _transitive_irs(function)
        for ir in irs:
            if type(ir).__name__ != "Assignment":
                continue
            target = _base_written_state_var(ir, state_vars)
            if target in proven_registries:
                queue_functions.add(full_name)
                break
    # What matures must be caller-chosen, or every cooldown reads as a timelock.
    arbitrary_executors = _arbitrary_execution_functions(effects)
    structural = bool(proven_registries and queue_functions and (execute_functions & arbitrary_executors))

    queue_functions |= claims.get("timelock.schedule", set())
    execute_functions |= claims.get("timelock.execute", set())

    standard = bool(claims.get("timelock.schedule") and claims.get("timelock.execute"))
    has_timelock = structural or standard

    if not has_timelock:
        pattern: Any = "none"
    elif standard:
        pattern = "oz_timelock"
    else:
        pattern = "custom"

    evidence = []
    if has_timelock:
        by_full_name = {getattr(f, "full_name", getattr(f, "name", "")): f for f in functions}
        for signature in sorted(queue_functions | execute_functions):
            function = by_full_name.get(signature)
            if function is not None:
                evidence.append(_source_evidence(function, project_dir))

    return {
        "has_timelock": has_timelock,
        "pattern": pattern,
        "delay": None,
        "delay_source": "not_read",
        "delay_variables": sorted(_timelock_delay_variables(contract, registries, queue_functions))
        if has_timelock
        else [],
        # Gated on the verdict: the bare structural pair would restate the over-claim.
        "queue_execute_functions": sorted(queue_functions | execute_functions) if has_timelock else [],
        "authorized_roles": sorted({role["role"] for role in role_definitions}) if has_timelock else [],
        "evidence": evidence,
    }


def _determine_control_model(
    contract, semantic_control: SemanticControlAnalysis, timelock: TimelockAnalysis
) -> ControlModel:
    del contract
    # ``None`` must not read as a proven absence.
    if timelock["has_timelock"] is True:
        return "governance"
    return semantic_control["pattern"]


def _build_tracking_hints(
    semantic_control: SemanticControlAnalysis,
    upgradeability: UpgradeabilityAnalysis,
    pausability: PausabilityAnalysis,
    timelock: TimelockAnalysis,
) -> list[TrackingHint]:
    hints: list[TrackingHint] = []
    for owner_variable in semantic_control["owner_variables"]:
        hints.append({"kind": "owner_variable", "label": owner_variable, "source": owner_variable})
    for admin_variable in semantic_control["admin_variables"]:
        hints.append({"kind": "admin_variable", "label": admin_variable, "source": admin_variable})
    for role in semantic_control["role_definitions"]:
        hints.append({"kind": "role", "label": role["role"], "source": role["role"]})
    for pause_variable in pausability["pause_variables"]:
        hints.append({"kind": "pause_flag", "label": pause_variable, "source": pause_variable})
    for slot in upgradeability["implementation_slots"]:
        hints.append({"kind": "proxy_slot", "label": slot, "source": slot})
    for delay_variable in timelock["delay_variables"]:
        hints.append({"kind": "timelock_delay", "label": delay_variable, "source": delay_variable})

    seen = set()
    deduped = []
    for hint in hints:
        key = (hint["kind"], hint["label"], hint["source"])
        if key in seen:
            continue
        seen.add(key)
        deduped.append(hint)
    return deduped
