"""Callee-parameter binding and per-frame tree normalization."""

from __future__ import annotations

import logging
from copy import deepcopy
from typing import TYPE_CHECKING, Any, cast

from eth_utils.crypto import keccak

from services.resolution.caller_sources import CALLER_SOURCES as _CALLER_SOURCES
from services.static.contract_analysis_pipeline.predicate_types import (
    LeafPredicate,
    PredicateTree,
)
from services.static.contract_analysis_pipeline.shared import external_bool_leaf_is_gate_shape

from .telemetry import _pass_live_read_memo, _state_var_lookup_key

if TYPE_CHECKING:
    from .core import EvaluationContext

logger = logging.getLogger("services.resolution.predicate_evaluator")


def _callee_argument_operands(
    leaf: LeafPredicate,
    *,
    callee_signature: str | None,
    callee_selector: str | None,
) -> list[dict[str, Any]]:
    args: list[dict[str, Any]] = []
    for raw_operand in leaf.get("operands") or []:
        if not isinstance(raw_operand, dict):
            continue
        operand = cast(dict[str, Any], raw_operand)
        if _is_target_call_operand(operand, callee_signature=callee_signature, callee_selector=callee_selector):
            continue
        args.append(deepcopy(operand))
    return args


def _is_target_call_operand(
    operand: dict[str, Any],
    *,
    callee_signature: str | None,
    callee_selector: str | None,
) -> bool:
    if operand.get("source") != "external_call":
        return False
    op_sig = operand.get("callee_signature")
    if callee_signature and isinstance(op_sig, str) and op_sig == callee_signature:
        return True
    op_selector = operand.get("callee_selector")
    if callee_selector and isinstance(op_selector, str) and op_selector == callee_selector:
        return True
    return False


def _bind_callee_parameters(tree: PredicateTree, call_args: list[dict[str, Any]]) -> PredicateTree:
    bound = _bind_value(deepcopy(tree), call_args)
    return cast(PredicateTree, bound) if isinstance(bound, dict) else tree


def _normalize_operand_for_call_arg(
    operand: dict[str, Any],
    frame: Any,
    ctx: EvaluationContext,
    *,
    callee_contract_address: str | None = None,
    rpc_url: str | None = None,
    block: int | None = None,
) -> dict[str, Any]:
    source = operand.get("source")
    if source in _CALLER_SOURCES:
        return {"source": "root_caller"}
    if source == "external_call":
        outer = getattr(getattr(ctx, "adapter", None), "_outer_ctx", None)
        constant = _resolve_static_external_call_operand(
            operand,
            callee_contract_address=callee_contract_address,
            rpc_url=rpc_url,
            block=block,
            chain_id=getattr(outer, "chain_id", None),
            memo=_pass_live_read_memo(outer),
        )
        if constant is not None:
            return constant
    if source == "self_address":
        value = getattr(frame, "current_address_this", None) or getattr(frame, "executing_contract_address", None)
        if isinstance(value, str) and value.startswith("0x"):
            return {"source": "constant", "constant_value": value.lower()}
    if source == "computed" and operand.get("computed_kind") == "msg.sig":
        selector = getattr(frame, "current_msg_sig", None) or getattr(frame, "current_function_selector", None)
        if isinstance(selector, str) and selector.startswith("0x"):
            return {"source": "constant", "constant_value": selector.lower()}
    if source == "parameter":
        bound = _bound_parameter_operand(operand, frame)
        if bound is not None:
            return _normalize_operand_for_call_arg(
                bound,
                frame,
                ctx,
                callee_contract_address=callee_contract_address,
                rpc_url=rpc_url,
                block=block,
            )
    if source == "state_variable":
        name = _state_var_lookup_key(operand)
        value = ctx.state_var_values.get(name) if isinstance(name, str) else None
        if isinstance(value, str) and value.startswith("0x") and len(value) in {42, 66}:
            return {"source": "constant", "constant_value": value.lower()}
    return deepcopy(operand)


def _resolve_static_external_call_operand(
    operand: dict[str, Any],
    *,
    callee_contract_address: str | None,
    rpc_url: str | None,
    block: int | None,
    chain_id: int | None = None,
    memo: dict[Any, Any] | None = None,
) -> dict[str, Any] | None:
    signature = operand.get("callee_signature")
    selector = operand.get("callee_selector")
    if not isinstance(signature, str) or not signature.endswith("()"):
        return None
    if not isinstance(selector, str) or not selector.startswith("0x") or len(selector) != 10:
        selector = _selector_for_signature(signature)
    if not selector or not isinstance(callee_contract_address, str) or not callee_contract_address.startswith("0x"):
        return None
    if not rpc_url:
        return None
    block_tag = hex(block) if isinstance(block, int) else "latest"
    # Pass-scoped dedup of this nullary callee getter (deterministic at a fixed block). Successful reads only:
    # a revert/transient error is never cached, so behavior is byte-identical to the un-memoized path.
    memo_key = ("ext_operand", rpc_url, callee_contract_address.lower(), selector, block_tag)
    if memo is not None and memo_key in memo:
        return {"source": "constant", "constant_value": memo[memo_key]}
    try:
        from services.clients.rpc import rpc_request

        raw = rpc_request(
            rpc_url,
            "eth_call",
            [{"to": callee_contract_address.lower(), "data": selector}, block_tag],
            retries=1,
            chain_id=chain_id,
        )
    except Exception:
        return None
    if not isinstance(raw, str) or not raw.startswith("0x") or len(raw) < 66:
        return None
    constant_value = "0x" + raw[-64:].lower()
    if memo is not None:
        memo[memo_key] = constant_value
    return {"source": "constant", "constant_value": constant_value}


def _normalize_tree_for_frame(tree: PredicateTree, frame: Any) -> PredicateTree:
    normalized = _normalize_value_for_frame(deepcopy(tree), frame)
    return cast(PredicateTree, normalized) if isinstance(normalized, dict) else tree


def _normalize_value_for_frame(value: Any, frame: Any, seen_parameters: frozenset[int] = frozenset()) -> Any:
    if isinstance(value, list):
        return [_normalize_value_for_frame(item, frame, seen_parameters) for item in value]
    if not isinstance(value, dict):
        return value

    source = value.get("source")
    if source == "msg_sender":
        sender = getattr(frame, "current_msg_sender", None)
        if isinstance(sender, str) and sender.startswith("0x"):
            return {"source": "constant", "constant_value": sender.lower()}
    if source == "self_address":
        address_this = getattr(frame, "current_address_this", None) or getattr(
            frame, "executing_contract_address", None
        )
        if isinstance(address_this, str) and address_this.startswith("0x"):
            return {"source": "constant", "constant_value": address_this.lower()}
    if source == "computed" and value.get("computed_kind") == "msg.sig":
        selector = getattr(frame, "current_msg_sig", None) or getattr(frame, "current_function_selector", None)
        if isinstance(selector, str) and selector.startswith("0x"):
            return {"source": "constant", "constant_value": selector.lower()}
    if source == "parameter":
        idx = value.get("parameter_index")
        if isinstance(idx, int):
            if idx in seen_parameters:
                return deepcopy(value)
            seen_parameters = seen_parameters | {idx}
        bound = _bound_parameter_operand(value, frame)
        if bound is not None:
            return _normalize_value_for_frame(bound, frame, seen_parameters)

    return {k: _normalize_value_for_frame(v, frame, seen_parameters) for k, v in value.items()}


def _bound_parameter_operand(operand: dict[str, Any], frame: Any) -> dict[str, Any] | None:
    idx = operand.get("parameter_index")
    bound_params = getattr(frame, "bound_parameters", ()) or ()
    if isinstance(idx, int) and 0 <= idx < len(bound_params):
        bound = bound_params[idx]
        return deepcopy(bound) if isinstance(bound, dict) else None
    return None


def _bind_value(value: Any, call_args: list[dict[str, Any]]) -> Any:
    if isinstance(value, list):
        return [_bind_value(item, call_args) for item in value]
    if not isinstance(value, dict):
        return value
    if value.get("source") == "parameter":
        idx = value.get("parameter_index")
        if isinstance(idx, int) and 0 <= idx < len(call_args):
            return deepcopy(call_args[idx])
    out = {k: _bind_value(v, call_args) for k, v in value.items()}
    leaf = out.get("leaf")
    if isinstance(leaf, dict):
        _promote_bound_caller_leaf(leaf)
    return out


def _promote_bound_caller_leaf(leaf: dict[str, Any]) -> None:
    if leaf.get("authority_role") != "business":
        return
    if leaf.get("kind") not in {"equality", "membership", "external_bool"}:
        return
    if leaf.get("kind") == "external_bool" and not external_bool_leaf_is_gate_shape(
        leaf.get("callee_state_mutability"),
        leaf.get("gate_kind"),
        leaf.get("callee_signature"),
    ):
        # An external_bool leaf may only be promoted to proven delegated
        # authority when the static plane's discriminator says the callee is
        # gate-shaped (view/pure ACL read, own-storage library consume, or the
        # void merkle-witness carve-out). A nonview value-movement callee
        # (``require(token.transferFrom(user, …))`` with ``user``
        # caller-bound) stays ``business``: the caller-bound argument is the
        # funds subject, not an authorization subject. A ``None``
        # (not-determined) mutability likewise stays ``business`` — same as
        # the discriminator's own (None, nonview) handling: a not-determined
        # input must not mint the proven delegated-authority state.
        return
    operands = leaf.get("operands") or []
    key_sources = (leaf.get("set_descriptor") or {}).get("key_sources") or []
    has_caller = any(_is_caller_source(item) for item in [*operands, *key_sources] if isinstance(item, dict))
    if has_caller:
        leaf["authority_role"] = "delegated_authority"
        leaf["references_msg_sender"] = True


def _is_caller_source(item: dict[str, Any]) -> bool:
    return item.get("source") in _CALLER_SOURCES


def _tree_for_signature_or_selector(
    trees: dict[str, Any],
    *,
    callee_signature: str | None,
    callee_selector: str | None,
) -> PredicateTree | None:
    """Find a predicate tree by exact ABI signature or selector."""
    if callee_signature and callee_signature in trees:
        tree = trees[callee_signature]
        return cast(PredicateTree, tree) if isinstance(tree, dict) else None
    if callee_selector:
        for signature, tree in trees.items():
            if not isinstance(signature, str):
                continue
            if _selector_for_signature(signature) == callee_selector and isinstance(tree, dict):
                return cast(PredicateTree, tree)
    return None


def _selector_for_signature(signature: str) -> str | None:
    if "(" not in signature or not signature.endswith(")"):
        return None
    return "0x" + keccak(text=signature).hex()[:8]
