"""Summary and compatibility views for contract analysis."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from eth_utils.crypto import keccak

from schemas.contract_analysis import (
    ContractClassification,
    ControlModel,
    PausabilityAnalysis,
    RiskLevel,
    RoleDefinition,
    SemanticControlAnalysis,
    SlitherFinding,
    SlitherSummary,
    TimelockAnalysis,
    TrackingHint,
    UpgradeabilityAnalysis,
)

from .constants import (
    SEVERITY_ORDER,
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
    """True iff some leaf in ``tree`` carries
    ``authority_role IN {caller_authority, delegated_authority}``.
    This structural inclusion gate excludes side-condition trees that
    only carry time/reentrancy/pause/business roles."""
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
    """Walk a predicate_tree and return the unique state-variable / role
    operand names referenced by any leaf."""
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
    """Carry sink IDs through from the semantic effects record."""
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


# ---------------------------------------------------------------------------
# Structural detection helpers (name-independent, AST/IR-based)
# ---------------------------------------------------------------------------

# Known ERC20 function selectors (decimal form as Slither represents them)
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

# Canonical 4-byte selectors for standardized access-control entrypoints,
# keyed by ABI selector (interface params normalized to ``address``). Matched
# on the *standard* — a contract can't stay IAccessControl / Solmate-Auth
# compatible while changing these — so a rename can't dodge detection, while a
# bespoke scheme falls through to its function name (a false-negative by
# design, never a wrong tag). Both labels carry a capability tag downstream
# ("roles" / "authority").
#
# Role MEMBERSHIP is matched here, not by the predicate post-pass: a
# caller-keyed *data* map (e.g. LayerZero's per-sender ``composeQueue``) is
# structurally indistinguishable from a caller-keyed ACL, so "writes a
# caller_authority membership var" over-fires (``sendCompose`` reads as role
# management). Ownership has no such ambiguity — a scalar compared to the
# caller is an owner — so it stays in the post-pass.
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
    """Effect label for a standardized access-control entrypoint (OZ
    AccessControl role grants, Solmate RolesAuthority setters, Solmate Auth
    setAuthority), matched by the function's own canonical ABI selector.
    Returns None for everything else."""
    try:
        signature = function.solidity_signature
    except (ValueError, AttributeError):
        # solidity_signature raises for struct-param functions; not relevant here.
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
    """Check if the function (or any internal function it calls) sends ETH via .call{value:}."""
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
    """Scan IR for abi.encodeWithSelector calls with known ERC20 selectors."""
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
                # Extract the selector value from IR
                # IR: TMP = SOLIDITY_CALL abi.encodeWithSelector()(2835717307,to,amount)
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


# ---------------------------------------------------------------------------
# Main effect label function
# ---------------------------------------------------------------------------


def _effect_labels(function, graph_entry: dict | None) -> list[str]:
    """The retained fact-tier labels: value-flow selector facts, low-level
    value movement, canonical access-control selectors, and sink-kind
    capabilities. The semantic labels (ownership, pause, upgrade, hook,
    supply, authority) are minted by the Plane-1 claims registry and folded
    into ``effect_labels`` by ``project_effect_labels`` — this function no
    longer guesses them from single-function structure."""
    labels: set[str] = set()
    sink_kinds = set(graph_entry.get("sink_kinds", [])) if graph_entry else set()

    # Asset send: low-level .call{value:} (ETH transfer)
    if _function_has_low_level_value_call(function):
        labels.add("asset_send")

    # Encoded selectors: abi.encodeWithSelector with known ERC20 selectors
    labels.update(_detect_encoded_selectors(function))
    labels.update(_labels_from_external_call_sinks(graph_entry))

    # Roles / authority replacement matched on the canonical ABI selector of a
    # standardized access-control entry point (OZ AccessControl, Solmate).
    access_control = _access_control_label(function)
    if access_control:
        labels.add(access_control)

    if sink_kinds.intersection({"contract_creation"}):
        labels.add("contract_deployment")
    if sink_kinds.intersection({"delegatecall"}):
        labels.add("delegatecall_execution")
    if sink_kinds.intersection({"selfdestruct"}):
        labels.add("selfdestruct_capability")

    # Downgrade generic external_contract_call when a more specific label applies
    if labels.intersection({"asset_pull", "asset_send", "arbitrary_external_call", "mint", "burn"}):
        labels.discard("external_contract_call")

    return _dedupe_strings(list(labels))


def _extract_value_flows(function) -> list[dict]:
    """Extract detailed value flow info from standard selectors.

    Returns a list of dicts:
        {"direction": "in"|"out"|"mint"|"burn"|"eth_out",
         "token_var": "rewardsToken"|None,
         "token_type": "IERC20"|"address"|None,
         "method": "transfer"|"call{value}"|etc,
         "is_parameter": True if the caller chooses the address in ``token_var``}

    ``token_var`` names the caller-selectable address of the flow: the token
    contract for a high-level ERC-20 call, the RECIPIENT for a native send (an
    ETH send has no token). ``is_parameter`` says that address is one of THIS
    function's own parameters — a nested helper's formal is not an ABI slot and
    so is never reported here (the effects lattice's ``target_param_index``
    resolves those interprocedurally)."""
    flows: list[dict] = []
    param_names = {p.name.lower() for p in function.parameters}

    for _ct, call_ir in function.all_high_level_calls():
        ir_str = str(call_ir)
        if "dest:" not in ir_str:
            continue

        # Extract dest var name and function name
        dest_part = ir_str.split("dest:")[1]
        var_name = dest_part.split("(")[0].strip()
        var_type = ""
        if "(" in dest_part:
            var_type = dest_part.split("(")[1].split(")")[0]

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
                "is_parameter": var_name.lower() in param_names,
            }
        )

    # Low-level calls with value: ETH transfer
    visited: set[int] = set()

    def _check_low_level(fn, is_entry: bool) -> None:
        fn_id = id(fn)
        if fn_id in visited:
            return
        visited.add(fn_id)
        for node in fn.nodes:
            for ir in node.irs:
                ir_str = str(ir)
                if "LOW_LEVEL_CALL" in ir_str and "value:" in ir_str:
                    # Only a send sited in the entry's OWN body can name its
                    # recipient in the entry's ABI; one hop inside a helper the
                    # destination is a callee formal, meaningless to a caller, so
                    # it stays unnamed here rather than being asserted fixed.
                    dest = getattr(ir, "destination", None) if is_entry else None
                    dest_name = getattr(dest, "name", None)
                    recipient = dest_name if isinstance(dest_name, str) and dest_name.lower() in param_names else None
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
    factory_functions = []
    evidence = []
    if isinstance(effects, dict):
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
        "is_factory": bool(factory_functions),
        "factory_functions": sorted(factory_functions),
        "evidence": evidence,
    }


def _build_semantic_control_summary(
    contract,
    project_dir: Path,
    predicate_trees: Mapping[str, Any] | None,
    effects: Mapping[str, Any] | None,
) -> SemanticControlAnalysis:
    """Build the semantic control summary from semantic sources only.

    Semantic-function inclusion is structural: a function is included iff
    EITHER its predicate tree contains a leaf with
    ``authority_role IN {caller_authority, delegated_authority}`` OR
    its effects record carries a sensitive sink (state_write,
    external_call, delegatecall, contract_creation, selfdestruct).

    Role definitions come from role keys observed in predicate-tree leaves.
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
        # Structural inclusion gate: caller/delegated authority leaf OR
        # sensitive effect. Pause/reentrancy/business/time-only trees do not
        # admit a function into the semantic summary.
        if not (has_caller_authority_leaf or has_sensitive_sink):
            continue

        # Source effect/effect_target/effect_label/action_summary from the
        # per-function effects record. If the effects artifact is missing,
        # leave these summary fields empty rather than inferring a second path.
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

        # Auxiliary reporting fields are derived only from predicate-tree
        # leaves and the semantic effects artifact.
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


def _detect_pausability(
    contract,
    project_dir: Path,
    pause_info: Mapping[str, Any] | None = None,
) -> PausabilityAnalysis:
    """Detect pausability structurally from the semantic ``PauseInfo`` export.

    ``pause_info`` (returned by ``apply_reentrancy_pause_pass``) carries
    the structural pause-state-var set and toggle-function list.

    Modifiers that read a structural pause var are surfaced as
    ``gating_modifiers``. ``pause_functions`` / ``unpause_functions``
    are derived from the toggle list by inspecting which value the
    function writes (true = pause, false = unpause); when the structural
    classification can't disambiguate, every toggle function is listed in
    both pause and unpause.
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
                # Ambiguous polarity (parameter-driven setPaused(bool)
                # or branched writes): surface as both.
                pause_functions.add(full_name)
                unpause_functions.add(full_name)

    modifiers = _all_modifiers(contract)
    gating_modifiers: list[str] = []
    evidence = []
    if pause_var_set:
        for modifier in modifiers:
            read_names = {getattr(v, "name", "") for v in getattr(modifier, "state_variables_read", []) or []}
            if read_names & pause_var_set:
                gating_modifiers.append(modifier.name)
                evidence.append(_source_evidence(modifier, project_dir))

    return {
        "is_pausable": bool(pause_functions or unpause_functions or gating_modifiers or pause_state_vars),
        "pause_functions": sorted(pause_functions),
        "unpause_functions": sorted(unpause_functions),
        "gating_modifiers": sorted(gating_modifiers),
        "pause_variables": sorted(pause_state_vars),
        "authorized_roles": [],
        "evidence": evidence,
    }


def _classify_pause_toggle_polarity(function, pause_vars: set[str]) -> str:
    """Return ``"pause"`` if ``function`` writes one of ``pause_vars``
    with a true-ish constant, ``"unpause"`` if false-ish, or ``""`` if
    the polarity can't be determined statically.

    Walks IR Assignment ops for ``var = <const>`` shapes; anything else
    (param write, cross-branch toggle, derived value) returns ambiguous."""
    polarities: set[str] = set()
    for node in getattr(function, "nodes", []) or []:
        for ir in getattr(node, "irs", []) or []:
            op = type(ir).__name__
            if op != "Assignment":
                continue
            lvalue = getattr(ir, "lvalue", None)
            target = getattr(lvalue, "name", None)
            if isinstance(target, str):
                # Strip Slither SSA suffix.
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


def _detect_timelock(contract, project_dir: Path, role_definitions: list[RoleDefinition]) -> TimelockAnalysis:
    del contract, project_dir, role_definitions
    return {
        "has_timelock": False,
        "pattern": "none",
        "delay_variables": [],
        "queue_execute_functions": [],
        "authorized_roles": [],
        "evidence": [],
    }


def _summarize_slither(slither_output: dict) -> SlitherSummary:
    detectors = slither_output.get("results", {}).get("detectors", [])
    counts = {impact: 0 for impact in SEVERITY_ORDER}
    for detector in detectors:
        impact = detector.get("impact", "Informational")
        counts.setdefault(impact, 0)
        counts[impact] += 1

    key_findings: list[SlitherFinding] = []
    for detector in sorted(detectors, key=lambda item: SEVERITY_ORDER.get(item.get("impact", ""), 99))[:10]:
        description = str(detector.get("description", "")).strip().split("\n")[0]
        key_findings.append(
            {
                "check": detector.get("check", "unknown"),
                "impact": detector.get("impact", "Unknown"),
                "confidence": detector.get("confidence", "Unknown"),
                "description": description,
            }
        )

    return {
        "detector_counts": counts,
        "key_findings": key_findings,
    }


def _derive_static_risk_level(detector_counts: dict[str, int]) -> RiskLevel:
    if detector_counts.get("High", 0) > 0:
        return "high"
    if detector_counts.get("Medium", 0) > 0:
        return "medium"
    if sum(detector_counts.values()) > 0:
        return "low"
    return "unknown"


def _determine_control_model(
    contract, semantic_control: SemanticControlAnalysis, timelock: TimelockAnalysis
) -> ControlModel:
    del contract
    if timelock["has_timelock"]:
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
