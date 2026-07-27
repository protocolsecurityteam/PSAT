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


def _resolve_cast_head(head: Any, def_by_id: dict[int, Any]) -> Any:
    """Follow ``TypeConversion`` casts from a Slither temporary back to the named
    variable it aliases.

    A library-wrapped pull binds its token to a temporary — the real line is
    ``IERC20(address(eETH)).safeTransferFrom(...)``, a DOUBLE cast — so the call
    head is ``TMP_n`` whose own name (``"TMP_1127"``) carries no signal a consumer
    can act on. When ``head`` is a temporary defined by a cast, walk the cast chain
    to the operand underneath and return it. Scope is deliberately narrow:

    * TypeConversion edges only. Following an ``Assignment`` from a reassigned
      local would, in the non-SSA IR (no Phi), pick an arbitrary branch's value.
    * temporary-rooted only. The loop consults the def map only while the current
      value IS a temporary, so a state variable or parameter is returned unchanged
      — an assigned state var is never walked PAST to its rvalue.

    A mapping element (``ReferenceVariable``, e.g. ``tokens[id]``) or a computed
    value is not temporary-rooted, so it is returned unchanged and names no getter.
    Reads typed IR attributes only; never ``str(ir)``."""
    from slither.slithir.variables.temporary import TemporaryVariable  # type: ignore[import]

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
    """A non-SSA ``{id(lvalue) -> defining IR}`` over ``function`` and every
    internal/library callee reachable from it.

    The sink emitter and this value-flow walk read ``node.irs`` (not
    ``irs_ssa``), so the SSA def maps built elsewhere in the pipeline point at
    different operand objects and cannot serve a cast resolution over ``irs``."""
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
    resolves those interprocedurally).

    Every fact below is read off the IR object (``destination``, ``call_value``,
    the resolved callee): the call's ``repr`` is a debug rendering that can be
    reformatted upstream without any signal that this stopped working."""
    flows: list[dict] = []
    parameters = {id(p) for p in function.parameters}
    def_by_id = _function_ir_def_map(function)

    for _ct, call_ir in function.all_high_level_calls():
        destination = getattr(call_ir, "destination", None)
        if destination is None:
            continue
        # A library-wrapped or double-cast receiver arrives as a temporary; resolve
        # it to the state var it aliases so ``token_var`` names a real getter rather
        # than ``TMP_n`` (which fabricates a hint that seeds nothing downstream).
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

    # Low-level calls with value: ETH transfer
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
                # Only a send sited in the entry's OWN body can name its
                # recipient in the entry's ABI; one hop inside a helper the
                # destination is a callee formal, meaningless to a caller, so
                # it stays unnamed here rather than being asserted fixed.
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
    # ``is_factory`` is the only field here that is NOT derived from the IR: it
    # is read off the effects artifact's ``contract_creation`` sinks. When that
    # artifact is degraded (``core`` substitutes ``{"schema_version", "error"}``
    # if ``build_effects`` raises) there is no sink list to be empty, and
    # ``false`` would assert that a contract deploys nothing on the strength of
    # never having looked.
    #
    # The other fields ARE IR-derived -- ``contract.ercs()` plus a
    # signature/event match -- and run on every parse regardless of the Slither
    # DETECTOR pass, which has never run in this pipeline. So ``standards: []``
    # is a measured absence, not a silent one: it is non-empty on 31 of the 88
    # local contracts and covers every real token among them (EETH, WeETH,
    # Lido, FiatTokenV2_2, WithdrawRequestNFT...). Nulling it would suppress a
    # true negative, so it stays a list.
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


def _claims_plane_ran(effects: Mapping[str, Any] | None) -> bool:
    """Did the Plane-1 claims matcher complete and write onto this artifact?

    ``core`` runs the two planes under **separate** ``try``/``except`` blocks —
    ``build_effects`` at ``core.py:225-235`` and
    ``build_claims``/``attach_claims_to_effects``/``project_effect_labels`` at
    ``core.py:243-250``, the latter with its own ``record_degraded(phase=
    "claims")``. So a fully populated ``functions`` map proves the **effects**
    plane ran and says nothing about the claims plane: when only the second
    block raises, every record is present and every record is claim-free.

    The discriminator is the ``claims`` KEY, not its contents.
    ``attach_claims_to_effects`` sets ``record["claims"]`` on every function
    record — to ``[]`` where the function earned no claim — and
    ``build_effects`` never emits the key, so its presence is exactly "the
    claims matcher completed". Its *absence* is why a detector that can only
    see a latch/timelock through claims must answer not-determined rather than
    ``false``.

    An artifact with no externally-observable functions at all is likewise
    not-determined: there is no record to carry the key, so nothing here can
    tell a clean claims run from a missing one."""
    functions = (effects or {}).get("functions")
    if not isinstance(functions, Mapping):
        return False
    return any(isinstance(record, Mapping) and "claims" in record for record in functions.values())


_PAUSE_CLAIM_POLARITY = {"pause.set": "pause", "pause.unset": "unpause"}


def _pause_claims(effects: Mapping[str, Any] | None) -> tuple[set[str], set[str], set[str]]:
    """``(pause_functions, unpause_functions, flag_paths)`` from the Plane-1
    ``pause.set`` / ``pause.unset`` claims carried on the effects artifact.

    ``PauseAnalyzer`` (Plane-0) only ever sees a flag that is a top-level
    scalar state variable, which is why ``is_pausable`` was false on 33 of the
    46 local contracts that publish ``pause*`` entry points: the Veda family
    keeps its latch in a struct member (``accountantState.isPaused``) and the
    EtherFi / OZ-v5 family keeps it behind an ERC-7201 namespaced slot, and
    neither reaches ``contract.state_variables``. The claims matcher resolves
    both through member-path facts and is strictly the better-evidenced
    detector, so the summary reads it rather than re-deriving it.

    It is also what keeps the EigenLayer bitmap family OUT: ``pause(uint256)``
    assigns the new bitmap from a *parameter*, so the matcher's toggle polarity
    is not a definite constant bool and it fails closed. Measured: 0 of the 8
    bitmap contracts mint a ``pause.*`` claim."""
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
) -> PausabilityAnalysis:
    """Detect pausability from the semantic ``PauseInfo`` export **and** the
    Plane-1 pause claims.

    ``pause_info`` (returned by ``apply_reentrancy_pause_pass``) carries
    the structural pause-state-var set and toggle-function list.

    Modifiers that read a structural pause var are surfaced as
    ``gating_modifiers``. ``pause_functions`` / ``unpause_functions``
    are derived from the toggle list by inspecting which value the
    function writes (true = pause, false = unpause); when the structural
    classification can't disambiguate, every toggle function is listed in
    both pause and unpause.

    ``is_pausable`` is three-state. ``None`` is *not determined*: the structural
    pass found nothing AND the claims matcher — the only detector that can see a
    struct-member or namespaced latch — did not complete, which is a different
    fact from both of them running and finding no latch. The test for that is
    :func:`_claims_plane_ran`, i.e. whether claims were attached; a populated
    ``functions`` map only proves the *effects* plane ran, and ``core``
    degrades the two independently (``core.py:225-235`` vs ``:243-250``).
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

    claim_pause, claim_unpause, claim_flags = _pause_claims(effects)
    pause_functions |= claim_pause
    unpause_functions |= claim_unpause

    modifiers = _all_modifiers(contract)
    gating_modifiers: list[str] = []
    evidence = []
    # A claim flag may be a dotted path (``accountantState.isPaused``); a
    # modifier reads the BASE variable, so match on that.
    gate_var_set = pause_var_set | {path.split(".", 1)[0] for path in claim_flags}
    if gate_var_set:
        for modifier in modifiers:
            read_names = {getattr(v, "name", "") for v in getattr(modifier, "state_variables_read", []) or []}
            if read_names & gate_var_set:
                gating_modifiers.append(modifier.name)
                evidence.append(_source_evidence(modifier, project_dir))

    if pause_functions or unpause_functions or gating_modifiers or pause_state_vars:
        is_pausable: bool | None = True
    elif _claims_plane_ran(effects):
        is_pausable = False
    else:
        # The claims matcher is the only detector that can see a struct-member
        # or namespaced latch, and it is the one that did not run. Publishing
        # ``false`` off the structural pass alone asserts the absence of a
        # latch that pass could not have found: it answers ``false`` on 22 of
        # the 33 local contracts that demonstrably do have one. A populated
        # ``functions`` map is NOT the test — that is the effects plane, which
        # ``core`` degrades independently of the claims plane.
        is_pausable = None

    return {
        "is_pausable": is_pausable,
        "pause_functions": sorted(pause_functions),
        "unpause_functions": sorted(unpause_functions),
        "gating_modifiers": sorted(gating_modifiers),
        # Structural flags stay as bare names; claim flags carry their member
        # path, which is the only handle on WHICH struct member is the latch.
        "pause_variables": sorted(set(pause_state_vars) | claim_flags),
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


# ---------------------------------------------------------------------------
# Timelock detection (STATIC half only -- see _detect_timelock)
# ---------------------------------------------------------------------------

_TIMELOCK_QUEUE_CLAIMS = frozenset({"timelock.schedule"})
_TIMELOCK_EXECUTE_CLAIMS = frozenset({"timelock.execute"})
_TIMELOCK_CLAIMS = frozenset({"timelock.schedule", "timelock.execute", "timelock.cancel", "timelock.set_delay"})

# Slither renders these as SolidityVariableComposed; ``now`` is the pre-0.7 spelling.
_TIME_SOURCE_NAMES = frozenset({"block.timestamp", "now", "block.number"})

# How far the queue/maturity walks chase internal helpers. OZ needs 3
# (`execute` -> `_beforeCall` -> `isOperationReady`); the cap bounds the walk on
# contracts with deep internal call graphs.
_TIMELOCK_CALL_DEPTH = 4


def _timelock_claim_functions(effects: Mapping[str, Any] | None) -> dict[str, set[str]]:
    """``claim_id -> {signature}`` for the ``timelock.*`` claims on the effects
    artifact. The claims matcher recognises the published OZ
    ``TimelockController`` ABI (``getMinDelay`` + ``hashOperation`` + schedule +
    execute), which is the standard-exact half of this detector."""
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
    """Signatures carrying the ``exec.arbitrary`` claim -- a call whose target
    AND calldata come from the caller. It is the discriminator between a
    timelock (queue an arbitrary action, execute it once matured) and a
    cooldown (one hard-coded operation, delayed)."""
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
    """Every IR in ``function``'s body plus, recursively, its internal/library
    callees' and applied modifiers'. Cycle-safe, depth-bounded.

    The timelock invariant is split across helpers in every real
    implementation (OZ puts the write in ``_schedule`` and the maturity check
    two frames below ``execute``), so a body-only walk sees neither half."""
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
    """Every value name that ``seeds`` flow FORWARD into, over ``lvalue`` edges."""
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
    """``registry_var -> {other state vars in its derivation}``.

    A *registry* is a state variable assigned a value that a
    ``block.timestamp`` / ``block.number`` read flows into: the "this operation
    matures at T" write that is the queue half of every timelock. The
    accompanying set is the state variables that also flow into that value --
    the delay, when the delay is stored rather than passed."""
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
    """The contract state variable an Assignment writes, through a mapping/
    struct reference if need be. ``None`` when the write is to a local."""
    lvalue = getattr(ir, "lvalue", None)
    for candidate in (lvalue, getattr(lvalue, "points_to_origin", None), getattr(lvalue, "points_to", None)):
        name = getattr(candidate, "name", None)
        if isinstance(name, str) and name in state_vars:
            return name
    return None


def _maturity_gate_functions(contract, registries: set[str]) -> dict[str, set[str]]:
    """``registry_var -> {signature}`` for entry points that revert unless a
    registry value has matured against the clock.

    The require and the comparison do not have to sit in the same node: they
    routinely sit in different helpers (OZ's ``_beforeCall`` requires what
    ``isOperationReady`` computes), and the transitive walk's scope is what
    bounds "this revert reads this registry" -- the same relaxation
    ``ReentrancyAnalyzer._search_revert_reading_var`` already makes."""
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
    """The clock may reach the comparison through one temporary."""
    sources = _backward_sources(irs, _ir_reads(ir))
    return bool(sources & _TIME_SOURCE_NAMES)


def _registry_sources(irs: list[Any], names: set[str]) -> set[str]:
    return _backward_sources(irs, names)


def _backward_sources(irs: list[Any], names: set[str]) -> set[str]:
    """Every value name that flows INTO ``names``, over ``lvalue -> read`` edges."""
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
    """Where the delay VALUE lives -- the storage the live half would read.

    Two sources: a state variable that flows into the maturity write (a stored
    delay), and a mutable integer state variable the queue path reads (OZ's
    ``require(delay >= getMinDelay())`` bottoms out in ``_minDelay``; the
    per-operation delay is a parameter and only its floor is on chain).

    The second rule is deliberately recall-generous -- it names every mutable
    integer the queue path touches, not only the one arithmetic proves is the
    delay. It is a POINTER for the live half, not a claim about the value, and
    the value itself is never published from here (see ``_detect_timelock``).
    Constants and mappings are excluded: neither is a configurable delay."""
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
    """Prove, from source alone, that THIS CONTRACT IS A TIMELOCK.

    The invariant is structural and chain-free: some state variable is written
    with a value the clock (``block.timestamp`` / ``block.number``) flows into
    -- the queue half -- and some other entry point reverts unless that same
    variable has matured against the clock -- the execute half. Both halves
    live in internal helpers in every real implementation, so both walks are
    transitive.

    **That pair alone is NOT sufficient, and asserting it was would be an
    over-claim.** Measured on the 88 local contracts, the bare structural pair
    fires on 19 and only 3 are timelocks: it also matches a Teller's per-user
    ``shareLockPeriod`` transfer cooldown (6 contracts), a blacklist expiry, an
    EigenLayer withdrawal/activation delay and several rate-limiter refill
    windows. What separates a governance timelock from a cooldown is WHAT
    matures: a timelock delays an action chosen by the caller AT QUEUE TIME,
    a cooldown delays one specific hard-coded operation. So the structural half
    additionally requires the maturity-gated function to carry an
    ``exec.arbitrary`` claim -- caller-supplied target and calldata. With that
    requirement the structural half fires on exactly the 3, and would have
    credited 16 contracts with a protective delay they do not have without it.

    ``pattern`` is ``oz_timelock`` when the claims plane recognises the
    published ``TimelockController`` ABI, ``custom`` when only the structure
    (including the arbitrary-execution requirement) is there.

    **THE DELAY VALUE IS NOT READ HERE, AND MUST NOT BE DEFAULTED.** inv 9
    makes the delay the credit-bearing fact (EtherFiTimelock's is 10 days), and
    reading it needs ``getMinDelay()`` on chain. This module has no chain, no
    ``chain_id`` and no RPC handle, and inventing one -- or defaulting the
    delay -- would fabricate a protective credit, which inv 1 ranks worse than
    a false adverse. So ``delay`` is ``None`` and ``delay_source`` is
    ``"not_read"`` until a chain is threaded here. ``delay_variables`` names
    WHERE the value lives, which is the part source can prove.

    ``has_timelock`` is three-state, and ``False`` is only published when BOTH
    determinants had their inputs. Both of them live on the claims plane: the
    structural half is gated on ``exec.arbitrary`` and the standard half on
    ``timelock.schedule``/``timelock.execute``, so an effects artifact the
    claims matcher never wrote to makes both empty for a reason that has
    nothing to do with the contract. ``None`` therefore covers two cases —
    no IR to walk, and no claims plane (:func:`_claims_plane_ran`, which
    ``core`` can degrade independently of the effects plane; ``core.py:225-235``
    vs ``:243-250``). Publishing ``False`` on either is asserting an absence
    nothing looked for, and ``_determine_control_model`` would then drop
    ``governance`` off the back of it.
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
    # What matures has to be an action the CALLER chose, not a hard-coded one:
    # otherwise every per-user cooldown, blacklist expiry and rate-limit refill
    # window in the corpus reads as a governance timelock (measured: 19 hits,
    # 3 real). ``exec.arbitrary`` is the claims plane's proof of a
    # caller-supplied target + calldata.
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
        "queue_execute_functions": sorted(queue_functions | execute_functions),
        "authorized_roles": sorted({role["role"] for role in role_definitions}) if has_timelock else [],
        "evidence": evidence,
    }


def _slither_detector_output_present(slither_output: Any) -> bool:
    """Did the detector pass produce a result document at all?

    ``slither_results.json`` is read with a ``{}`` default, and ``{}`` used to
    flow straight into ``detector_counts = {High: 0, Medium: 0, ...}`` -- a
    positive assertion of zero findings for a pass that never ran. It has never
    run: the writer (``StaticWorker._run_slither_phase``) was removed when
    vulnerability-detector triage was split out, and the file is absent on
    75/75 production artifacts."""
    return isinstance(slither_output, Mapping) and isinstance(slither_output.get("results"), Mapping)


def _summarize_slither(slither_output: dict) -> SlitherSummary:
    if not _slither_detector_output_present(slither_output):
        # NOT ``{impact: 0}``. Absent counts and zero counts are different
        # facts and only one of them is a clean bill of health.
        return {
            "detector_output": "absent",
            "detector_counts": None,
            "key_findings": None,
        }

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
        "detector_output": "present",
        "detector_counts": counts,
        "key_findings": key_findings,
    }


def _derive_static_risk_level(detector_counts: dict[str, int] | None) -> RiskLevel | None:
    """``None`` = the detector pass did not run. ``"clean"`` = it ran and found
    nothing. The old code answered ``"unknown"`` for both, which is why
    ``risk_level`` reads ``unknown`` on 92/92 local rows -- indistinguishable
    from a contract Slither had cleared."""
    if detector_counts is None:
        return None
    if detector_counts.get("High", 0) > 0:
        return "high"
    if detector_counts.get("Medium", 0) > 0:
        return "medium"
    if sum(detector_counts.values()) > 0:
        return "low"
    return "clean"


def _determine_control_model(
    contract, semantic_control: SemanticControlAnalysis, timelock: TimelockAnalysis
) -> ControlModel:
    del contract
    # ``is True``, not truthiness: ``None`` is not-determined and must not be
    # read as a proven absence of governance either.
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
